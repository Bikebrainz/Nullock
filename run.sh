#!/bin/bash

# Compile the Java source files
echo "Compiling Java source files..."
javac --module-path ./lib --add-modules javafx.controls,javafx.fxml -d ./bin src/app/*.java

# Check if compilation was successful
if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

echo "Compilation successful!"

# Copy FXML file to bin directory
echo "Copying FXML file..."
cp src/app/app.fxml bin/app/

# Run the application
echo "Running application..."
java --module-path ./lib --add-modules javafx.controls,javafx.fxml -cp ./bin app.App
