mod signatures;
mod pii_detector;

use wasm_bindgen::prelude::*;
use serde::Serialize;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisResult {
    pub request_size: usize,
    pub file_type_from_analysis: String,

        #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pii_detected: Vec<String>
}

#[wasm_bindgen]
pub fn analyze_request(
    url: &str, 
    method: &str, 
    body_bytes: Vec<u8>, 
    total_size: usize
) -> JsValue {
    let file_type = signatures::identify_format(&body_bytes).to_string();
    let pii_list = pii_detector::detect_pii(&body_bytes);

    let result = AnalysisResult {
        request_size: total_size,
        file_type_from_analysis: file_type,
        pii_detected: pii_list
    };

    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}