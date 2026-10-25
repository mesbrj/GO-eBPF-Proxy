// Fixture for check C18: a module whose code reaches language.Parse in
// golang.org/x/text v0.3.5 (GO-2021-0113, fixed in v0.3.7), so `make vuln`
// run here must exit 2. Never upgrade this dependency.
module example.com/vulnmod

go 1.25.0

require golang.org/x/text v0.3.5
