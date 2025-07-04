use sha2::{Sha256, Digest as _};

const LENGTH_THRESHOLD: usize = 6;
const SIGNATURE_VERSION: u8 = 0;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct SignatureMode {
    pub class: bool,
    pub id: bool,
    pub text: bool,
}

impl From<String> for SignatureMode {
    fn from(s: String) -> Self {
        let mut mode = SignatureMode { class: false, id: false, text: false };
        for c in s.chars() {
            match c {
                'c' => mode.class = true,
                'i' => mode.id = true,
                't' => mode.text = true,
                _ => {}
            }
        }
        mode
    }
}

impl From<SignatureMode> for String {
    fn from(mode: SignatureMode) -> Self {
        let mut s = String::new();
        if mode.class {
            s.push('c');
        }
        if mode.id {
            s.push('i');
        }
        if mode.text {
            s.push('t');
        }
        s
    }
}

fn get_node_self_signature(node: &kuchikiki::NodeRef, mode: SignatureMode) -> String {
    let mut signature = format!("v{}:{}:", SIGNATURE_VERSION, <SignatureMode as Into<String>>::into(mode));
    if node.text_contents().trim().is_empty() {
        return String::new();
    }

    if let Some(element) = node.as_element() {
        signature.push_str(&element.name.local);
        let attributes = element.attributes.borrow();
        if mode.id {
            if let Some(id) = attributes.get("id") {
                signature.push_str(&id);
            }
        }
        if mode.class {
            if let Some(class) = attributes.get("class") {
                signature.push_str(&class);
            }
        }
    }

    if mode.text {
        if let Some(text) = node.as_text() {
            signature.push_str(&text.borrow().to_string());
        }
    }
    signature
}

pub fn get_node_signature(node: &kuchikiki::NodeRef, mode: SignatureMode) -> String {
    if node.text_contents().trim().len() < LENGTH_THRESHOLD {
        return String::new();
    }

    let mut signature = get_node_self_signature(node, mode);

    let mut child = node.first_child();
    while let Some(ref c) = child {
        let child_signature = get_node_signature(c, mode);
        signature.push_str(&child_signature);
        child = c.next_sibling();
    }
    
    if signature.is_empty() {
        return signature;
    }

    let mut hasher = Sha256::new();
    hasher.update(signature);
    let hash = hasher.finalize();
    format!("v{}:{}:{}", SIGNATURE_VERSION, <SignatureMode as Into<String>>::into(mode), hex::encode(hash))
}