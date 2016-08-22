package asapi

var gconfig *Config

func init() {
	gconfig = &Config{
		ASURL:           "http://127.0.0.1:8099",
		ClientID:        "57a999b57a03b59ebb9b11b0",
		ClientSecret:    "9389211575bfa749b3efdfc3bcd2114e3344e025",
		ServiceIdentify: "TEST",
	}
}
