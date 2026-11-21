use secretguard::docker::DockerScanner;
use secretguard::SecretGuardEngine;
use std::fs;

#[test]
fn test_docker_scan_catches_baked_env_and_copy() {
    let engine = SecretGuardEngine::new();
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_docker_test_{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let dockerfile_path = temp_dir.join("Dockerfile");
    let content = r#"FROM node:18-alpine
WORKDIR /app
ENV STRIPE_SECRET=sk-proj-1234567890abcdef1234567890abcdef1234567890
COPY . .
RUN npm install
CMD ["npm", "start"]
"#;
    fs::write(&dockerfile_path, content).unwrap();

    let report = DockerScanner::scan_dockerfile(&dockerfile_path, &engine).unwrap();
    assert!(!report.clean);
    assert_eq!(report.leaks.len(), 2);
    assert_eq!(report.leaks[0].instruction, "ENV");
    assert_eq!(report.leaks[1].instruction, "COPY");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_clean_dockerfile_passes() {
    let engine = SecretGuardEngine::new();
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_docker_clean_{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let dockerfile_path = temp_dir.join("Dockerfile");
    let content = r#"FROM node:18-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --only=production
COPY src ./src
USER node
CMD ["node", "src/index.js"]
"#;
    fs::write(&dockerfile_path, content).unwrap();

    let report = DockerScanner::scan_dockerfile(&dockerfile_path, &engine).unwrap();
    assert!(report.clean);
    assert_eq!(report.leaks.len(), 0);

    let _ = fs::remove_dir_all(&temp_dir);
}
