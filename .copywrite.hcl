schema_version = 1

project {
  license          = "BUSL-1.1"
  copyright_holder = "Dit"
  copyright_year   = 2026

  # Build artifacts and coverage output that must not carry license headers.
  header_ignore = [
    "build/**",
    ".health/**",
    "**/*.out",
  ]
}
