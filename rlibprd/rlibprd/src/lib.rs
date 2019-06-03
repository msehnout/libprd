mod unbound;
mod validator;

#[cfg(test)]
mod tests {
    use crate::validator::Validator;

    #[test]
    fn resolve() {
        if let Some(mut v) = Validator::try_new() {
            v.resolve("557d8ff0f0f4c6c9fc7140670cc85400dcee5aeb1ac2412e90f41e45._openpgpkey.fedoraproject.org")
        } else {
            println!("epic fail");
        }
    }
}
