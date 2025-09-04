/// Middleware to inject a trace ID into request headers.
use axum::{
    extract::Request,
    http::{HeaderValue, header::HeaderName},
    response::Response,
};
// use http::{header::HeaderName, HeaderValue};
use once_cell::sync::Lazy;
use std::{
    future::Future,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};
use tower::{Layer, Service};
use tracing::{
    Span,
    // info,
};

static X_TRACE_ID: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_str("x-trace-id").expect("Invalid header name"));

#[derive(Clone, Debug)]
pub struct TraceIdMiddleware<S> {
    inner: S,
    header_name: HeaderName,
}

impl<S> TraceIdMiddleware<S> {
    pub fn new(inner: S, header_name: HeaderName) -> Self {
        Self { inner, header_name }
    }
}

impl<S: Default> Default for TraceIdMiddleware<S> {
    fn default() -> Self {
        TraceIdMiddleware {
            inner: Default::default(),
            header_name: X_TRACE_ID.clone(),
        }
    }
}

impl<S, B> Service<Request<B>> for TraceIdMiddleware<S>
where
    S: Service<Request<B>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Checks if the inner service is ready to process requests.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Injects the trace ID into the request headers and calls the inner service.
    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let header_name = self.header_name.clone();

        let trace_id: String = {
            let span = Span::current();
            span.id()
                .map(|id| id.into_u64().to_string())
                .unwrap_or_default()
        };

        // TODO: Handle Span IDs that are not u64 ???
        // let trace_id: String = match Span::current().id() {
        //     Some(id) => {
        //         if id.is_u64() {
        //             id.into_u64().to_string() // Handle u64 IDs
        //         } else {
        //             format!("{:?}", id) // Fallback to some other string representation
        //         }
        //         // if let Some(u64_id) = id.into_u64() {
        //         //     u64_id.to_string() // Handle u64 IDs
        //         // } else {
        //         //     format!("{:?}", id) // Fallback to some other string representation
        //         // }
        //     },
        //     None => String::from(""), // Return an empty string or some placeholder
        // };

        // Update the headers with the trace ID if found
        if !trace_id.is_empty() {
            if let Ok(header_value) = HeaderValue::from_str(&trace_id) {
                req.headers_mut().insert(header_name, header_value);
            } else {
                tracing::warn!("Failed to create header value from trace ID: {}", trace_id);
            }
        }

        let fut = self.inner.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

#[derive(Clone, Debug)]
pub struct TraceIdLayer {
    header_name: HeaderName,
}

impl TraceIdLayer {
    pub fn new(header_name: HeaderName) -> Self {
        Self { header_name }
    }
}

impl Default for TraceIdLayer {
    fn default() -> Self {
        Self {
            header_name: X_TRACE_ID.clone(),
        }
    }
}

impl<S> Layer<S> for TraceIdLayer {
    type Service = TraceIdMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceIdMiddleware {
            inner,
            header_name: self.header_name.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{convert::Infallible, sync::Once};
    // use http::Request;
    use axum::{
        body::Body,
        http::{HeaderValue, Request, Response, header::HeaderName},
    };
    use tower::{
        // layer::util::Stack,
        // ServiceBuilder,
        ServiceExt,
        service_fn,
    };
    // use hyper::body::to_bytes;
    // use http_body_util::BodyExt;
    use tracing::{
        self,
        // info,
        Level,
        info_span,
    };
    use tracing_subscriber;

    // type ServiceBuilderType = ServiceBuilder<Stack<TraceIdLayer, tower::layer::util::Identity>>;

    static INIT: Once = Once::new();

    fn init_tracing() {
        INIT.call_once(|| {
            // Try to initialize tracing subscriber, ignore if already set
            // This is safe for test environments where subscriber might already exist
            let _ = tracing_subscriber::fmt()
                .with_max_level(Level::INFO)
                .try_init();
        });
    }

    fn create_test_service(
        layer: TraceIdLayer,
    ) -> impl Service<Request<Body>, Response = Response<Body>, Error = Infallible> {
        let header_name = layer.header_name.clone();
        let mock_service = service_fn(move |req: Request<Body>| {
            let header_name = header_name.clone();
            async move {
                // Extract the trace ID from the request headers
                let trace_id = req
                    .headers()
                    .get(header_name.clone())
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();

                // Create a response and include the trace ID in the response headers
                let mut response = Response::new(Body::empty());
                response.headers_mut().insert(
                    header_name.clone(),
                    HeaderValue::from_str(&trace_id).unwrap(),
                );
                Ok::<_, Infallible>(response)
            }
        });

        TraceIdMiddleware::new(mock_service, layer.header_name)
    }

    // fn create_test_service_with_layers(layers: Vec<TraceIdLayer>) -> impl Service<Request<Body>, Response = Response<Body>, Error = Infallible> {
    //     let mut service_builder = ServiceBuilder::new();
    //     info!("Adding layers to new ServiceBuilder object...");
    //     for layer in layers {
    //         info!("Adding layer: {:?}", layer.header_name);
    //         service_builder = service_builder.layer(layer);
    //     }

    //     info!("Return created service...");

    //     // service_builder.service_fn(|req: Request<Body>| async move {
    //     //     let trace_ids: Vec<String> = req.headers().iter()
    //     //         .filter_map(|(name, value)| value.to_str().ok().map(|v| format!("{}:{}", name, v)))
    //     //         .collect();
    //     //     Ok::<_, Infallible>(Response::new(Body::from(trace_ids.join(";"))))
    //     // })

    //     // Build the final service with `service_fn` and wrap the response as needed
    //     service_builder.service(service_fn(|req: Request<Body>| async move {
    //         let trace_ids: Vec<String> = req.headers()
    //             .iter()
    //             .filter_map(|(name, value)| {
    //                 value.to_str().ok().map(|v| format!("{}:{}", name, v))
    //             })
    //             .collect();

    //         // Respond with the concatenated trace IDs
    //         let response_body = trace_ids.join(";");
    //         let response = Response::new(Body::from(response_body));
    //         Ok::<_, Infallible>(response)
    //     }))

    // }

    async fn run_test_with_layer(layer: TraceIdLayer) -> (String, String) {
        let svc = create_test_service(layer.clone());

        let span = info_span!("test_span");
        let _guard = span.enter();

        let request = Request::new(Body::empty());
        let response = svc.oneshot(request).await.unwrap();

        let header_trace_id = response
            .headers()
            .get(&layer.header_name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("unknown-trace-id")
            .to_string();

        let span_trace_id = span
            .id()
            .map(|id| id.into_u64().to_string())
            .unwrap_or_else(|| "".to_string());

        (header_trace_id, span_trace_id)
    }

    #[tokio::test]
    /// This test ensures that the trace ID injected into the request headers matches the
    /// trace ID of the current tracing span. It simulates a request and compares the trace
    /// ID in the headers with the span ID to ensure they are identical. This is crucial for
    /// correlating requests and tracing spans in distributed systems.
    /// The test uses the default header name "X-Trace-ID" for the trace ID.
    async fn test_default_trace_id_header() {
        // thread::sleep(Duration::from_millis(100));
        init_tracing();
        let layer = TraceIdLayer::default();
        let (trace_id, span_trace_id) = run_test_with_layer(layer).await;
        assert_eq!(
            trace_id, span_trace_id,
            "Trace ID does not match the span's trace ID"
        );
    }

    #[tokio::test]
    /// This test demonstrates how to customize the trace ID header name by using a custom
    /// header name. The test verifies that the custom trace ID is injected into the request
    /// headers and matches the trace ID of the current span. This test is useful for scenarios
    /// where you need to use a different header name for trace IDs.
    async fn test_custom_trace_id_header() {
        // thread::sleep(Duration::from_millis(200));
        init_tracing();
        let custom_header = HeaderName::from_static("x-custom-id");
        let layer = TraceIdLayer::new(custom_header);
        let (trace_id, span_trace_id) = run_test_with_layer(layer).await;
        assert_eq!(
            trace_id, span_trace_id,
            "Trace ID does not match the span's trace ID"
        );
    }

    #[tokio::test]
    /// This test ensures that the trace ID is properly injected into the request headers
    /// by the `TraceIdLayer` middleware. The test simulates a simple HTTP request and
    /// checks if the default "X-Trace-ID" header is present in the response headers.
    async fn test_trace_id_in_response() {
        // thread::sleep(Duration::from_millis(300));
        init_tracing();
        let layer = TraceIdLayer::default();
        let svc = create_test_service(layer.clone());

        let span = info_span!("test_span");
        let _guard = span.enter();

        let request = Request::new(Body::empty());
        let response = svc.oneshot(request).await.unwrap();

        assert!(
            response.headers().contains_key(layer.header_name),
            "Trace ID header not found in response"
        );
    }

    #[tokio::test]
    /// This test ensures that the trace ID injected into the request headers matches the
    /// trace ID of the current tracing span. It simulates a request and compares the trace
    /// ID in the headers with the span ID to ensure they are identical. This is crucial for
    /// correlating requests and tracing spans in distributed systems.
    async fn test_trace_id_matches_span() {
        // thread::sleep(Duration::from_millis(400));
        init_tracing();
        let layer = TraceIdLayer::default();
        let (trace_id, span_trace_id) = run_test_with_layer(layer).await;
        assert_eq!(
            trace_id, span_trace_id,
            "Trace ID does not match the span's trace ID"
        );
    }

    #[tokio::test]
    /// This test ensures that the trace ID is properly injected into the request headers
    /// by the `TraceIdLayer` middleware. The test simulates a simple HTTP request and
    /// checks if the default "X-Trace-ID" header is present in the response headers.
    async fn test_default_header_name() {
        // thread::sleep(Duration::from_millis(500));
        init_tracing();
        let layer = TraceIdLayer::default();
        println!(
            "TEST-03: 'test_default_header_name' --> Header name: {:?}",
            layer.header_name
        );
        assert_eq!(
            layer.header_name,
            &HeaderName::from_static("x-trace-id"),
            "Default header name should be 'x-trace-id'"
        );
    }

    // #[tokio::test]
    // /// This test verifies that the trace ID, generated by different `TraceIdLayer` instances,
    // /// is correctly propagated to the  inner layer. The test creates two layers with different
    // /// header names and checks if the trace IDs match in the response body. This test is useful
    // /// for verifying that the trace ID is correctly propagated through multiple layers.
    // async fn test_trace_id_propagation_through_multiple_layers() {
    //     thread::sleep(Duration::from_millis(600));
    //     init_tracing();
    //     let layer1 = TraceIdLayer::default();
    //     let layer2 = TraceIdLayer::new(HeaderName::from_static("x-another-trace-id"));

    //     // // Build the service with layers
    //     // let service_builder = ServiceBuilder::new()
    //     //     .layer(TraceIdLayer::default())  // Add a default layer to the chain
    //     //     .layer(TraceIdLayer::new(HeaderName::from_static("X-Another-ID")));  // Adding another custom layer

    //     let svc = ServiceBuilder::new()
    //         .layer(layer1.clone())
    //         .layer(layer2.clone())
    //         .service_fn(|req: Request<Body>| async move {
    //             let trace_id1 = req.headers().get(layer1.header_name.clone()).unwrap().to_str().unwrap().to_string();
    //             let trace_id2 = req.headers().get(layer2.header_name.clone()).unwrap().to_str().unwrap().to_string();
    //             Ok::<_, Infallible>(Response::new(Body::from(format!("{};{}", trace_id1, trace_id2))))
    //         });

    //     // let svc = create_test_service_with_layers(vec![layer1.clone(), layer2.clone()]);
    //     // let svc = create_test_service(service_builder)

    //     let span = info_span!("test_span");
    //     let _guard = span.enter();

    //     let request = Request::new(Body::empty());
    //     let response = svc.oneshot(request).await.unwrap();

    //     // let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    //     // let boxed_body = response.into_body().boxed();
    //     // let boxed_body = response.into_body().map_err(|e| axum::Error::new(e)).boxed();
    //     // let body = to_bytes(boxed_body).await.unwrap();
    //     // let body = to_bytes(response.into_body()).await.unwrap();
    //     // let body = to_bytes(axum::body::boxed(response.into_body())).await.unwrap();
    //     let boxed_body = response.into_body().boxed();
    //     let body = to_bytes(boxed_body).await.unwrap();

    //     let body_str = std::str::from_utf8(&body).unwrap();

    //     let trace_ids: Vec<&str> = body_str.split(';').collect();
    //     assert_eq!(trace_ids.len(), 2, "Expected two trace IDs in the response body");
    //     assert_eq!(trace_ids[0], trace_ids[1], "Trace IDs from different layers do not match");

    // }

    // #[tokio::test]
    // /// This test verifies that the trace ID is not injected into the response headers when
    // /// the header name is empty. The test creates a layer with an empty header name and checks
    // /// if the header is present in the response. This test is useful for ensuring that the
    // /// middleware does not inject the trace ID when the header name is invalid.
    // async fn test_trace_id_with_empty_header_name() {
    //     thread::sleep(Duration::from_millis(700));
    //     info!("TEST-07: a...");
    //     init_tracing();
    //     info!("TEST-07: b...");
    //     let empty_header = HeaderName::from_static("");
    //     info!("TEST-07: c...");
    //     let layer = TraceIdLayer::new(empty_header);
    //     info!("TEST-07: d...");
    //     let svc = create_test_service(layer.clone());

    //     info!("TEST-07: e...");
    //     let span = info_span!("test_span");
    //     let _guard = span.enter();

    //     info!("TEST-07: f...");
    //     let request = Request::new(Body::empty());
    //     let response = svc.oneshot(request).await.unwrap();

    //     info!("TEST-07: g...");
    //     info!("TEST-07: Response headers: {:?}", response.headers().contains_key(&layer.header_name));
    //     assert!(!response.headers().contains_key(layer.header_name), "Empty header name should not be present in response");
    // }

    // #[tokio::test]
    // /// This test verifies that the trace ID is not injected into the response headers when
    // /// the header name is invalid. The test creates a layer with an invalid header name and
    // /// checks if the header is present in the response. This test is useful for ensuring that
    // /// the middleware does not inject the trace ID when the header name is invalid.
    // async fn test_trace_id_with_invalid_header_name() {
    //     thread::sleep(Duration::from_millis(800));
    //     info!("TEST-08: a...");
    //     init_tracing();
    //     info!("TEST-08: b...");
    //     let invalid_header = HeaderName::from_static("invalid header name");
    //     info!("TEST-08: c...");
    //     let layer = TraceIdLayer::new(invalid_header);
    //     info!("TEST-08: d...");
    //     let svc = create_test_service(layer.clone());
    //     info!("TEST-08: e...");
    //     let span = info_span!("test_span");
    //     let _guard = span.enter();
    //     info!("TEST-08: f...");
    //     let request = Request::new(Body::empty());
    //     let response = ServiceExt::oneshot(svc, request).await.unwrap();
    //     info!("TEST-08: g...");
    //     assert!(!response.headers().contains_key(layer.header_name), "Invalid header name should not be present in response");
    // }
}
