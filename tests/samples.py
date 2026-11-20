"""Fake credentials for the tests.

They are assembled from pieces at import time so that no token-shaped literal sits in
the repository for a secret scanner to trip over. None of them is a real credential.
"""

AWS_KEY_ID = "AKIA" + "IOSFODNN7" + "EXAMPLE"
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0" * 2
GITHUB_PAT = "github_" + "pat_" + "11AAAAAAA0" + "abcdefghijklmnopqrstuv"
STRIPE_KEY = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
SLACK_TOKEN = "xoxb-" + "123456789012-" + "abcdefABCDEF"
GOOGLE_KEY = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
API_KEY = "sk-" + "proj-" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2"
JWT = ".".join(
    ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"]
)
PRIVATE_KEY = (
    "-----BEGIN " + "RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
    "-----END " + "RSA PRIVATE KEY-----"
)
