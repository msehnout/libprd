mod unbound;
mod validator;
mod email2domain;

#[cfg(test)]
mod tests {
    use crate::validator::Validator;
    use crate::email2domain::*;

    #[test]
    fn resolve() {
        if let Some(mut v) = Validator::try_new() {
            let domain = email2domain("fedora-29@fedoraproject.org").unwrap();
            v.resolve(&domain);
        } else {
            println!("epic fail");
        }
    }
}
