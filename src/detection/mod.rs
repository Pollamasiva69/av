//! Detection engines module

pub mod signature;
pub mod heuristic;
pub mod behavioral;
pub mod pe_analyzer;

pub use signature::SignatureDetector;
pub use heuristic::HeuristicDetector;
pub use behavioral::BehavioralDetector;
pub use pe_analyzer::PEAnalyzer;
