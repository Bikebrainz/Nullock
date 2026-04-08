<a id="readme-top"></a>

<div align="center">
  <img src="https://img.shields.io/github/contributors/gratonic/Nullock.svg?style=for-the-badge" alt="Contributors" />
  <img src="https://img.shields.io/github/forks/gratonic/Nullock.svg?style=for-the-badge" alt="Forks" />
  <img src="https://img.shields.io/github/stars/gratonic/Nullock.svg?style=for-the-badge" alt="Stargazers" />
  <img src="https://img.shields.io/github/issues/gratonic/Nullock.svg?style=for-the-badge" alt="Issues" />
  <img src="https://img.shields.io/github/license/gratonic/Nullock.svg?style=for-the-badge" alt="MIT License" />
</div>



<!-- PROJECT BANNER -->
<br />
<div align="center">
  <a href="https://github.com/gratonic/Nullock">
    <img src="./Images/Other/nullock_banner.jpeg" alt="Nullock Banner" width="100" height="100">
  </a>

  <h3 align="center">Nullock</h3>

  <p align="center">
    A FOSS MITM HTTP Proxy
    <br />
    <a href="https://github.com/gratonic/Nullock"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/gratonic/Nullock">View Demo</a>
    &middot;
    <a href="https://github.com/gratonic/Nullock/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    &middot;
    <a href="https://github.com/gratonic/Nullock/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Tech Stack</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



## About The Project

![Nullock][dashboard-screenshot]

Nullock is a free and open source Man In The Middle HTTP Proxy written in Java that aims to fill the gap between expensive, closed-source tools like Burpsuite Pro and legacy FOSS alternatives like OWASP Zap. Designed with Bug Bounty Hunters and The Web Hacking Community in mind, Nullock aims to provide users with a simple, fast, and modern GUI with a familiar Burpsuite-Like tool set. Written in honor of [NullSec](https://discord.gg/3QJBBkt8gW) and Sherlock, it gets its name by combining the two to get [Nullock](https://discord.gg/3QJBBkt8gW), reflecting the investigative nature of MITM Proxies.

If you are interested in contributing, writing a theme, or writing an extensions please follow the instructions below and/or read the documentation. All contributions, themes, and extensions are appreciated.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

More diagrams and drawings can be found [here](./Images/).

### Tech Stack

<img src="https://4.bp.blogspot.com/_crVRzfI94Bs/S8WI147NyRI/AAAAAAAAACw/nuDQdliHrho/s320/JavaFX.png" alt="JavaFX" width="75" height="75" />
<img src="https://netty.io/images/logo.png" alt="Netty" width="75" height="75" />
<img src="https://raw.githubusercontent.com/jmnote/z-icons/master/svg/java.svg" alt="Java" width="75" height="75" />

<p align="right">(<a href="#readme-top">back to top</a>)</p>



## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

### Prerequisites

Linux or Windows: x64 architecture
OpenJDK 21: https://openjdk.org 

### Installation/Setup

Linux:

1. clone the repo: 
```sh
git clone https://github.com/Gratonic/Nullock
```
2. change your directory to Nullock: 
```sh 
cd Nullock
```
3. change the installation file permissions (rwxr--r--): 
```sh 
chmod 744 install.sh 
```
4. run the installation file: 
```sh 
./install.sh 
```
5. change the run file permissions (rwxr--r--): 
```sh   
chmod 744 run.sh
```
6. run the run file: 
```sh 
./run.sh 
```

Windows:

1. clone the repo:
```sh 
git clone https://github.com/Gratonic/Nullock
```
2. Navigate to openjfx.io and [download](https://download2.gluonhq.com/openjfx/21.0.10/openjfx-21.0.10_windows-x64_bin-sdk.zip) the Windows x64 JavaFX SDK zip file
3. Unzip the JavaFX SDK zip
4. create a directory called 'lib' in the Nullock root directory (Nullock)
5. move everything in the created JavaFX directory's lib directory to the directory you just created (Nullock/lib)
6. delete the directory that was generated that was created by unzipping the JavaFX SDK zip file (and all its contents) and delete the JavaFX SDK zip file

## Usage

### Nullock 
Please refer to the <placeholder> for information on how to use Nullock. <!-- [Documentation](https://example.com) -->

### Themes API:
Please refer to the <placeholder> for information on how to use The Themes API. <!-- [Documentation](https://example.com) -->

### Extensions API:
Please refer to the <placeholder> for information on how to use The Extensions API. <!-- [Documentation](https://example.com) -->

<p align="right">(<a href="#readme-top">back to top</a>)</p>



## Roadmap

- [ ] Write the GUI
- [ ] Write the Proxy Core
- [ ] Add core functionality to the GUI
- [ ] Write the Extensions API
- [ ] Write the Themes API
- [ ] Add Multi-Language Support
    - [x] English
    - [ ] Spanish
    - [ ] German
    - [ ] Ukrainian
    - [ ] Russian
    - [ ] Chinese
    - [ ] Japanese

See the [open issues](https://github.com/gratonic/Nullock/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>



## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this tool better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement". 

If you have an extension for the tool and would like it advertised in the README please open an issue with the tag extension.

Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
3. Push to the Branch (`git push origin feature/AmazingFeature`)
4. Open a Pull Request

### Top contributors:

<a href="https://github.com/gratonic/Nullock/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=gratonic/Nullock"/>
</a>

<p align="right">(<a href="#readme-top">back to top</a>)</p>



## License

Distributed under the MIT License. See `LICENSE.md` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



## Contact

Feel free to email me or chat with me in the [NullSec Discord](https://discord.gg/3QJBBkt8gW)

Email: gratonic@proton.me
Discord: gratonic

Project Link: [https://github.com/gratonic/nullock](https://github.com/gratonic/nullock)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[dashboard-screenshot]: ./Images/Diagrams/nullock_dashboard.png
