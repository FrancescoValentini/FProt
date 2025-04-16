package common

import (
	"fmt"
	"os"
)

// Check if the file exists and is not a folder
func FileExistsAndNotDir(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}

	if info.IsDir() {
		return false, fmt.Errorf("%w: %v", ErrIsFolder, err)
	}

	return true, nil
}

// Reads the contents of a file
func ReadFile(path string) (string, error) {
	exists, err := FileExistsAndNotDir(path)
	if err != nil {
		return "", err
	}

	if !exists {
		return "", fmt.Errorf("%w: %v", ErrFileNotExist, err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrReadingFile, err)
	}

	return string(content), nil
}

// Writes the contents to a file only if the file does not already exist
func WriteFileIfNotExists(path string, content string) error {
	exists, err := FileExistsAndNotDir(path)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: %v", ErrFileExist, err)
	}

	err = os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWritingFile, err)
	}

	return nil
}
