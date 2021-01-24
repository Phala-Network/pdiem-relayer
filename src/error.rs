#[derive(Debug)]
pub enum Error {
  HyperError(hyper::error::Error),
  HttpError(hyper::http::Error),
  UriError(hyper::http::uri::InvalidUri),
  SerdeError(serde_json::error::Error),
  FailedToDecode,
  BadTransactionHash,
  FailedToGetResponse
}

impl From<hyper::error::Error> for Error {
  fn from(error: hyper::error::Error) -> Error {
      Error::HyperError(error)
  }
}

impl From<hyper::http::Error> for Error {
  fn from(error: hyper::http::Error) -> Error {
      Error::HttpError(error)
  }
}

impl From<hyper::http::uri::InvalidUri> for Error {
  fn from(error: hyper::http::uri::InvalidUri) -> Error {
    Error::UriError(error)
  }
}

impl From<serde_json::error::Error> for Error {
  fn from(error: serde_json::error::Error) -> Error {
    Error::SerdeError(error)
  }
}
