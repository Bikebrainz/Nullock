#!/usr/bin/env bash

# check if the user is in the root directory
if [[ "$(basename "$PWD")" != "Nullock" ]]; then
  echo "must be in the root directory (Nullock)" >&2
  exit 1
fi

# determine the users architecture
arch="$(uname -m)"

# create a temporary directory for the JavaFX SDK files
mkdir -p ./JavaFX

# library directory 
mkdir -p /lib

case "$arch" in
  x86_64|amd64)
    echo "fetching the JavaFX SDK"
    wget -q -O ~/JavaFX/zipped_up_shit.zip 'https://download2.gluonhq.com/openjfx/21.0.10/openjfx-21.0.10_linux-x64_bin-sdk.zip'
    
    echo "unpacking the JavaFX SDK files into ./lib"
    unzip -q ~/JavaFX/zipped_up_shit.zip -d ~/JavaFX/
    
    mv -n ~/JavaFX/javafx-sdk*/lib/*.jar ./lib/
    mv -n ~/JavaFX/javafx-sdk*/lib/*.so ./lib/ 
esac

rm -rf ~/JavaFX
