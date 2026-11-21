//! The names the Valkey `sid` store writes: a session named by its key, a
//! stem of this release's own that leaves the earlier release's records
//! unread, and every key of the store in one cluster slot. The live tests
//! are ignored by default: `VALKEY_URL=redis://127.0.0.1:6390
//! VALKEY_CLUSTER_URL=redis-cluster://127.0.0.1:7001 cargo test -p
//! axess-core --features testing,oauth,jwt-aws-lc,valkey -- --ignored
//! valkey_logout`. Each live test removes what it wrote, also when it fails.

use super::*;
use crate::session::id::SessionId;
use crate::testing::mock_random::MockRng;
use crate::testing::valkey_sweep::KeySweep;
use fred::types::{ClusterHash, CustomCommand};
use fred::util::redis_keyslot;
use std::collections::{BTreeMap, BTreeSet};

const ISS: &str = "https://idp.example.org";

/// A fresh prefix named by `tag`, whose keys are removed when the sweep is
/// dropped: at the end of the test that holds it, also when it fails.
fn sweep(tag: &str) -> KeySweep {
    crate::testing::valkey_sweep::on_node(&format!("names_{tag}"))
}

async fn client() -> Client {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let client = Client::new(Config::from_url(&url).expect("url"), None, None, None);
    client.init().await.expect("connect");
    client
}

/// A client that is never connected: a store on it that sends a command
/// gets no answer from a server.
fn idle_client() -> Client {
    Client::new(Config::default(), None, None, None)
}

/// A text from a token as the store writes it in a name, written out here
/// rather than through the store's own helper.
fn length_prefixed(text: &str) -> String {
    format!("{}:{text}", text.len())
}

/// Every key name that matches `pattern` on the node `client` talks to, by
/// `SCAN`, sorted. Braces are plain characters of a glob.
async fn names_matching(client: &Client, pattern: &str) -> Vec<String> {
    let mut cursor = "0".to_string();
    let mut found = Vec::new();
    loop {
        let (next, mut page): (String, Vec<String>) = client
            .custom(
                CustomCommand::new_static("SCAN", ClusterHash::FirstKey, false),
                vec![cursor.as_str(), "MATCH", pattern, "COUNT", "1000"],
            )
            .await
            .expect("SCAN");
        found.append(&mut page);
        if next == "0" {
            break;
        }
        cursor = next;
    }
    found.sort();
    found
}

/// Every name a store builds for one login: the mapping, the subject hash,
/// the session record and its set, and the stem the scripts extend.
fn names(store: &ValkeySidStore, key: &SidKey, subject: &str, session: &SessionKey) -> Vec<String> {
    vec![
        store.sid_key(key).expect("an accepted prefix"),
        store
            .subject_key(&key.0, subject)
            .expect("an accepted prefix"),
        store
            .session_record_key(session)
            .expect("an accepted prefix"),
        store.sids_key(session).expect("an accepted prefix"),
        format!(
            "{}{session}",
            store.sessions_stem().expect("an accepted prefix")
        ),
    ]
}

/// After a login's two writes the store holds exactly the four shapes of its
/// key list under `{<prefix>}:v2`, the mapping and the subject hash name the
/// session by its key's 64 characters, and no name, field or value holds the
/// session id in any form.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_logout_a_login_writes_the_four_names_and_names_its_session_by_the_key() {
    let sweep = sweep("shapes");
    let prefix = sweep.prefix().to_owned();
    let s = ValkeySidStore::new(client().await).with_prefix(prefix.clone());
    let id = SessionId::new(&MockRng::new(61));
    let session = SessionKey::of(&id);
    let user = axess_identity::testing::user("alice");
    let tenant = axess_identity::testing::tenant("acme");
    let key: SidKey = (ISS.to_string(), "sid-shapes".to_string());
    s.register_subject_session(ISS, "sub-shapes", Some(tenant), user, session)
        .await
        .unwrap();
    s.insert_displacing(
        key.clone(),
        "sub-shapes",
        Some(tenant),
        user,
        session,
        axess_clock::testing::MockClock::reference_time(),
    )
    .await
    .unwrap();

    let stem = format!("{{{prefix}}}:v2");
    let mapping = format!(
        "{stem}:sid:{}:{}",
        length_prefixed(ISS),
        length_prefixed("sid-shapes")
    );
    let subject = format!(
        "{stem}:sub:{}:{}",
        length_prefixed(ISS),
        length_prefixed("sub-shapes")
    );
    let record = format!("{stem}:ses:{session}");
    let set = format!("{stem}:ses:{session}:sids");
    let mut expected = vec![
        mapping.clone(),
        subject.clone(),
        record.clone(),
        set.clone(),
    ];
    expected.sort();
    let found = names_matching(&s.client, &format!("{{{prefix}}}*")).await;
    assert_eq!(found, expected, "the four shapes and no other name");

    let stored: String = s.client.get(&mapping).await.unwrap();
    let stored_json: serde_json::Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(
        stored_json["s"].as_str(),
        Some(session.to_string().as_str()),
        "the mapping names the session by its key"
    );
    let fields: Vec<String> = s.client.hkeys(&subject).await.unwrap();
    assert_eq!(
        fields,
        vec![session.to_string()],
        "the subject hash's field"
    );

    let mut texts = found.clone();
    texts.push(stored);
    texts.extend(s.client.hgetall::<Vec<String>, _>(&subject).await.unwrap());
    texts.push(s.client.get::<String, _>(&record).await.unwrap());
    texts.extend(s.client.smembers::<Vec<String>, _>(&set).await.unwrap());
    let hyphenated = id.to_string();
    let simple = hyphenated.replace('-', "");
    for text in &texts {
        assert!(!text.contains(&hyphenated), "{text} holds the id");
        assert!(!text.contains(&simple), "{text} holds the id's digits");
        assert!(
            !text.as_bytes().windows(16).any(|w| w == id.as_bytes()),
            "{text} holds the id's bytes"
        );
    }
    s.remove_session(&session).await.unwrap();
}

/// Records written by the earlier release, under the names it used and
/// naming their session by its id, are never read: a look-up finds nothing,
/// the subject's sessions are an empty list and no error, a removal removes
/// nothing, and the planted records are left as they were.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_logout_records_of_the_earlier_release_are_never_read() {
    let sweep = sweep("earlier");
    let prefix = sweep.prefix().to_owned();
    let c = client().await;
    let s = ValkeySidStore::new(c.clone()).with_prefix(prefix.clone());
    let id = SessionId::new(&MockRng::new(62));
    let user = axess_identity::testing::user("alice");
    let planted = plant_earlier_records(&c, &prefix, &id, &user).await;
    let before = read_planted(&c, &planted).await;

    let key: SidKey = (ISS.to_string(), "sid-old".to_string());
    assert!(
        s.get(&key, None).await.unwrap().is_none(),
        "no mapping read"
    );
    assert_eq!(
        s.subject_sessions(ISS, "sub-old", None).await,
        Ok(Vec::new()),
        "the earlier subject hash is not read"
    );
    assert_eq!(s.remove_session(&SessionKey::of(&id)).await, Ok(0));
    assert_eq!(
        read_planted(&c, &planted).await,
        before,
        "the planted records are untouched"
    );
    for name in planted {
        let _: i64 = c.del(name).await.unwrap();
    }
}

/// The four names the earlier release wrote for one login, written by raw
/// commands: a mapping and a subject field naming the session by its id, the
/// session record and its set of mappings.
async fn plant_earlier_records(
    c: &Client,
    prefix: &str,
    id: &SessionId,
    user: &UserId,
) -> Vec<String> {
    let mapping = format!(
        "{prefix}:sid:{}:{}",
        length_prefixed(ISS),
        length_prefixed("sid-old")
    );
    let subject = format!(
        "{prefix}:sub:{}:{}",
        length_prefixed(ISS),
        length_prefixed("sub-old")
    );
    let record = format!("{prefix}:ses:{id}");
    let set = format!("{prefix}:ses:{id}:sids");
    let mapping_json = serde_json::json!({
        "sub": "sub-old", "t": null, "u": user.to_string(), "s": id.to_string(), "at": 0
    })
    .to_string();
    let record_json =
        serde_json::json!({ "i": ISS, "u": user.to_string(), "k": subject }).to_string();
    let value = serde_json::json!({ "u": user.to_string(), "t": null }).to_string();
    let _: () = c
        .set(&mapping, mapping_json, None, None, false)
        .await
        .unwrap();
    let _: i64 = c.hset(&subject, (id.to_string(), value)).await.unwrap();
    let _: () = c
        .set(&record, record_json, None, None, false)
        .await
        .unwrap();
    let _: i64 = c.sadd(&set, mapping.clone()).await.unwrap();
    vec![mapping, subject, record, set]
}

/// What the planted names hold: the two strings, the hash and the set.
async fn read_planted(c: &Client, planted: &[String]) -> BTreeMap<String, String> {
    let mut held = BTreeMap::new();
    for name in [&planted[0], &planted[2]] {
        let text: Option<String> = c.get(name).await.unwrap();
        held.insert(name.clone(), format!("{text:?}"));
    }
    let hash: BTreeMap<String, String> = c.hgetall(&planted[1]).await.unwrap();
    held.insert(planted[1].clone(), format!("{hash:?}"));
    let set: BTreeSet<String> = c.smembers(&planted[3]).await.unwrap();
    held.insert(planted[3].clone(), format!("{set:?}"));
    held
}

/// Under the default prefix, one with a hash tag of its own, one that holds
/// a closing brace and one that opens a brace it does not close, every name
/// the store builds lies in one slot, for logins whose issuer, subject and
/// `sid` hold braces of their own.
#[test]
fn every_name_the_store_builds_lies_in_one_slot_under_an_accepted_prefix() {
    let expected_slots = [
        (DEFAULT_PREFIX, Some(10767)),
        ("{axess}:logout", Some(4448)),
        ("a}b", None),
        ("a{b", Some(13340)),
    ];
    for (prefix, expected) in expected_slots {
        let store = ValkeySidStore::new(idle_client()).with_prefix(prefix);
        let mut slots = BTreeSet::new();
        for i in 0..64u8 {
            let key: SidKey = (
                format!("https://idp{{{i}}}.example.org/}}{{"),
                format!("{{sid}}-{i}-}}"),
            );
            let subject = format!("}}sub{{{i}");
            let session = SessionKey::from_bytes([i; 32]);
            for name in names(&store, &key, &subject, &session) {
                slots.insert(redis_keyslot(name.as_bytes()));
            }
        }
        assert_eq!(slots.len(), 1, "{prefix}: the names lie in {slots:?}");
        if let Some(slot) = expected {
            assert_eq!(slots.first(), Some(&slot), "{prefix}");
        }
    }
}

/// Whether `answer` came back in time and is the refusal of a prefix that
/// would split the store.
fn refused<T>(answer: Result<Result<T, SidStoreError>, tokio::time::error::Elapsed>) -> bool {
    matches!(answer, Ok(Err(SidStoreError(text))) if text == REFUSED_PREFIX)
}

/// A prefix that is empty or begins with a closing brace would leave the
/// hash tag empty and split the store over several slots: every method
/// answers the refusal at once, on a client that was never connected, so
/// nothing was sent.
#[tokio::test]
async fn a_prefix_that_would_split_the_store_is_refused_by_every_method() {
    let user = axess_identity::testing::user("alice");
    let session = SessionKey::from_bytes([7; 32]);
    let key: SidKey = (ISS.to_string(), "sid".to_string());
    let at = axess_clock::testing::MockClock::reference_time();
    let displaced = DisplacedSid {
        subject: "sub".to_string(),
        tenant: None,
        user,
        session,
        inserted_at: at,
    };
    let wait = Duration::from_secs(2);
    for prefix in ["", "}x"] {
        let s = ValkeySidStore::new(idle_client()).with_prefix(prefix);
        let answers = [
            (
                "insert_displacing",
                refused(
                    tokio::time::timeout(
                        wait,
                        s.insert_displacing(key.clone(), "sub", None, user, session, at),
                    )
                    .await,
                ),
            ),
            (
                "restore_if_vacant",
                refused(
                    tokio::time::timeout(wait, s.restore_if_vacant(key.clone(), displaced.clone()))
                        .await,
                ),
            ),
            (
                "get",
                refused(tokio::time::timeout(wait, s.get(&key, None)).await),
            ),
            (
                "remove_if_session",
                refused(tokio::time::timeout(wait, s.remove_if_session(&key, &session)).await),
            ),
            (
                "register_subject_session",
                refused(
                    tokio::time::timeout(
                        wait,
                        s.register_subject_session(ISS, "sub", None, user, session),
                    )
                    .await,
                ),
            ),
            (
                "forget_subject_session",
                refused(
                    tokio::time::timeout(wait, s.forget_subject_session(ISS, &user, &session))
                        .await,
                ),
            ),
            (
                "subject_sessions",
                refused(tokio::time::timeout(wait, s.subject_sessions(ISS, "sub", None)).await),
            ),
            (
                "sweep_subject_candidates",
                refused(tokio::time::timeout(wait, s.sweep_subject_candidates(8)).await),
            ),
            (
                "remove_session",
                refused(tokio::time::timeout(wait, s.remove_session(&session)).await),
            ),
            (
                "evict_inserted_before",
                refused(tokio::time::timeout(wait, s.evict_inserted_before(at, 8)).await),
            ),
            (
                "evict_oldest",
                refused(tokio::time::timeout(wait, s.evict_oldest(8)).await),
            ),
            (
                "mapping_count",
                refused(tokio::time::timeout(wait, s.mapping_count()).await),
            ),
        ];
        for (method, was_refused) in answers {
            assert!(was_refused, "{prefix:?}: {method} was not refused");
        }
    }
}

/// The test that needs a cluster. `valkey_cluster` is the name a run on
/// one node leaves it out by (`--skip valkey_cluster`, and the filter of
/// the live mutation job), as it leaves out the other cluster suites.
mod valkey_cluster {
    use super::*;

    /// On a cluster, under the default prefix, a login's writes and every read
    /// and removal of the logout paths run: the scripts reach keys of one slot.
    #[tokio::test]
    #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
    async fn valkey_logout_cluster_the_store_runs_under_the_default_prefix() {
        let s = ValkeySidStore::new(crate::testing::valkey_cluster::cluster_client().await);
        // Under the default prefix the names are not under a prefix of the
        // test's: they are found by the run's text in the issuer and the `sid`,
        // and by the session's random key.
        let session = SessionKey::of(&SessionId::new(&axess_rng::SystemRng));
        let sweep = crate::testing::valkey_sweep::on_cluster("names_default")
            .also_holding(&session.to_string());
        let run = sweep.prefix();
        let issuer = format!("https://idp.example.org/{{{run}}}");
        let user = axess_identity::testing::user("alice");
        let key: SidKey = (issuer.clone(), format!("sid-{run}"));
        let at = axess_clock::testing::MockClock::reference_time();
        s.register_subject_session(&issuer, "sub-cluster", None, user, session)
            .await
            .expect("register_subject_session");
        s.insert_displacing(key.clone(), "sub-cluster", None, user, session, at)
            .await
            .expect("insert_displacing");
        assert_eq!(
            s.get(&key, None).await.expect("get").map(|e| e.1),
            Some(session)
        );
        assert_eq!(
            s.subject_sessions(&issuer, "sub-cluster", None)
                .await
                .expect("subject_sessions"),
            vec![(user, session)]
        );
        assert_eq!(
            s.remove_if_session(&key, &session)
                .await
                .expect("remove_if_session")
                .map(|e| e.1),
            Some(session)
        );
        s.register_subject_session(&issuer, "sub-cluster", None, user, session)
            .await
            .expect("register_subject_session again");
        s.insert_displacing(key.clone(), "sub-cluster", None, user, session, at)
            .await
            .expect("insert_displacing again");
        assert_eq!(s.remove_session(&session).await.expect("remove_session"), 1);
        assert!(s.get(&key, None).await.expect("get").is_none());
    }
}
