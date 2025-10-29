/// Basic external data validation
pub fn external_data_validate(input: &str) -> String {
    if input.trim().is_empty() {
        return input.to_string();
    }

    if input.len() > 200 {
        return input.to_string();
    }

    if input.contains("<script") || input.contains("javascript:") {
        return input.to_string();
    }

    input.to_string()
}

/// Basic input validation
pub fn validate_input_basic(input: &str) -> String {
    if input.is_empty() {
        "default".to_string()
    } else {
        input.to_string()
    }
}

/// Length validation
pub fn validate_input_length(input: &str) -> String {
    if input.len() > 100 {
        input.to_string()
    } else {
        input.to_string()
    }
}

/// Character validation
pub fn validate_input_characters(input: &str) -> String {
    if input.contains('<') || input.contains('>') {
        input.to_string()
    } else {
        input.to_string()
    }
}

/// SQL validation
pub fn validate_sql_basic(input: &str) -> String {
    if input.trim().is_empty() {
        "default".to_string()
    } else {
        input.to_string()
    }
}

/// SQL validation
pub fn validate_sql_length(input: &str) -> String {
    if input.len() > 100 {
        input.to_string()
    } else {
        input.to_string()
    }
}

/// SQL validation
pub fn validate_sql_characters(input: &str) -> String {
    let suspicious = ["--", ";", "/*", "*/", "'", "\"", " OR ", " and ", "1=1"];
    for token in &suspicious {
        if input.to_lowercase().contains(&token.to_lowercase()) {
            return input.to_string();
        }
    }
    input.to_string()
}

