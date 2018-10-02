#[macro_use] extern crate serde_derive;
extern crate serde;
#[macro_use] extern crate serde_json;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum Id {
    String(String),
    Number(i32),
    Null
}

#[derive(Serialize, Deserialize)]
pub struct Error {
    pub code: i32,
    pub message: String,
    pub data: serde_json::Value
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Request {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<serde_json::Value>,
    pub id: Option<Id>
}

impl Request {
    fn new(method: String, params: serde_json::Value, id: Id) -> Request {
        Request {
            jsonrpc: From::from("2.0"),
            method: method,
            params: Some(params),
            id: Some(id)
        }
    }
    fn new_notification(method: String, params: serde_json::Value) -> Request {
        Request {
            jsonrpc: From::from("2.0"),
            method: method,
            params: Some(params),
            id: None
        }
    }
    fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub result: serde_json::Value,
    pub error: Option<Error>
}

impl Response {
    fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request() {
        let req1 = Request::new(From::from("subtract"), json!([42, 23]), Id::Number(1));
        assert_eq!(req1.is_notification(), false);
        assert_eq!(
            req1,
            serde_json::from_str(r#"{
                "jsonrpc": "2.0",
                "method": "subtract",
                "params": [42, 23],
                "id": 1
            }"#).unwrap()
        );

        let req2 = Request::new_notification(From::from("subtract"), json!([42, 23]));
        assert_eq!(req2.is_notification(), true);
        assert_eq!(
            req2,
            serde_json::from_str(r#"{
                "jsonrpc": "2.0",
                "method": "subtract",
                "params": [42, 23]
            }"#).unwrap()
        );
    }
}
