use euclid::{dssa::types::AnalysisErrorType, frontend::dir};

#[derive(Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "type", content = "info", rename_all = "snake_case")]
pub enum KgraphError {
    #[error("Invalid connector name encountered: '{0}'")]
    InvalidConnectorName(String),
    #[error("Error in domain creation")]
    DomainCreationError,
    #[error("There was an error constructing the graph: {0}")]
    GraphConstructionError(orbit_constraint_graph::GraphError<dir::DirValue>),
    #[error("There was an error constructing the context")]
    ContextConstructionError(AnalysisErrorType),
    #[error("there was an unprecedented indexing error")]
    IndexingError,
}
