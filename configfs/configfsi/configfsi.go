// Package configfsi defines an interface for interaction with the TSM configfs subsystem.
package configfsi

// Client abstracts the filesystem operations for interacting with configfs files.
type Client interface {
	// MkdirTemp creates a new temporary directory in the directory dir and returns the pathname
	// of the new directory. Pattern semantics follow os.MkdirTemp.
	MkdirTemp(dir, pattern string) (string, error)
	// ReadFile reads the named file and returns the contents.
	ReadFile(name string) ([]byte, error)
	// WriteFile writes data to the named file, creating it if necessary. The permissions
	// are implementation-defined.
	WriteFile(name string, contents []byte) error
	// RemoveAll removes path and any children it contains.
	RemoveAll(path string) error
}
