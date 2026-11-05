// Fake credentials for the tests, assembled at runtime so secret scanners
// (and GitHub push protection) do not mistake the source for a real leak.
export const FAKE = {
  aws: "AKIA" + "IOSFODNN7" + "EXAMPLE",
  github: "gh" + "p_" + "Zq9".repeat(12),
  stripe: "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
  anthropic: "sk-" + "ant-api03-" + "x7Yq".repeat(8),
  openai: "sk-" + "proj-" + "Ab3D".repeat(8),
  slack: "xo" + "xb-" + "1234567890-0987654321-" + "abcDEF".repeat(4),
  google: "AI" + "za" + "SyD".repeat(11) + "x0",
  jwt: "ey" + "JhbGciOiJIUzI1NiJ9" + ".ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
  key: "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH " + "PRIVATE KEY-----",
  db: "postgres://admin:" + "S3cr3tPass" + "@db.internal:5432/prod",
  cisco: "enable secret 9 $9$" + "nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM",
  snmp: "snmp-server community " + "N0tPublic!" + " RO",
};
