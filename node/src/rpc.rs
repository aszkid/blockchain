use std::collections::HashMap;
use method::Method;

pub struct Server<'a> {
    pub methods: HashMap<String, Box<Method + 'a>>,
}

impl<'a> Server<'a> {
    pub fn new() -> Server<'a> {
        Server {
            methods: HashMap::new(),
        }
    }

    pub fn run(&self) {
        /*::rouille::start_server("127.0.0.1:8787", move |req| {
            Response::text("hi there")
        });*/
        //::rocket::ignite().mount("/", routes![self::index]).launch();
    }

    pub fn add_method<T: Method + 'a>(&mut self, m: T) {
        self.methods.insert(m.name().to_string(), Box::new(m));
    }
}
