//! The detection module is responsible for detecting and classifying bytecode regions (Init, Runtime, ConstructorArgs,
//! Auxdata, Padding.

pub mod dispatcher;
pub mod sections;

pub use dispatcher::{
    DispatcherInfo, ExtractionPattern, FunctionSelector, detect_function_dispatcher, has_dispatcher,
};

pub use sections::{
    Section, SectionKind, extract_runtime_instructions, locate_sections, validate_sections,
};
