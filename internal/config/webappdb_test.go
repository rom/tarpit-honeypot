package config

import "testing"

func TestAutoActivateWebappDB(t *testing.T) {
	c := &Config{Listeners: []Listener{
		{ID: "web", Proto: "tcp", Bind: "0.0.0.0:80", Handler: "http", Webapp: true},
	}}
	c.autoActivateWebappDB()
	var foundMySQL bool
	for _, l := range c.Listeners {
		if l.Handler == "mysql" && l.Bind == "0.0.0.0:3306" {
			foundMySQL = true
		}
	}
	if !foundMySQL {
		t.Errorf("webapp listener did not auto-add a MySQL on :3306; listeners=%v", c.Listeners)
	}
}

func TestAutoActivateWebappDBNoDupe(t *testing.T) {
	c := &Config{Listeners: []Listener{
		{ID: "web", Proto: "tcp", Bind: "10.0.0.5:80", Handler: "http", Webapp: true},
		{ID: "db", Proto: "tcp", Bind: "10.0.0.5:3306", Handler: "mysql"},
	}}
	n := len(c.Listeners)
	c.autoActivateWebappDB()
	if len(c.Listeners) != n {
		t.Errorf("operator MySQL present — should not add another; got %d listeners (was %d)", len(c.Listeners), n)
	}
}

func TestAutoActivateWebappDBNoWebapp(t *testing.T) {
	c := &Config{Listeners: []Listener{{ID: "web", Proto: "tcp", Bind: "0.0.0.0:80", Handler: "http"}}}
	c.autoActivateWebappDB()
	for _, l := range c.Listeners {
		if l.Handler == "mysql" {
			t.Error("no webapp => no auto MySQL")
		}
	}
}
