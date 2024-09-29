<h1 align="center">
  <br>
  <a href="https://gbounty.bountysecurity.ai/">
        <img src="static/gbounty-logo.png" width="400px" alt="GBounty">
  </a>
</h1>

<h4 align="center">Fast, reliable, and highly customizable website vulnerability scanner.</h4>

<p align="center">
<a href="https://twitter.com/GBountySecurity"><img src="https://img.shields.io/twitter/follow/GBountySecurity.svg?logo=twitter"></a>
</p>

<p align="center">
  •
  <a href="#install-gbounty">Install</a> •
  <a href="https://gbounty.net/documentation/" target="_blank">Documentation</a> •
</p>

---

Fast, reliable, and highly customizable website vulnerability scanner.

We have a [dedicated repository](https://github.com/bountysecurity/gbounty-profiles) that houses various type of
web vulnerability profiles contributed by security researchers and engineers.

> [!WARNING]  
> **This project is in active development.** Expect breaking changes with releases. 
> Review the release changelog before updating.

> [!CAUTION]  
> This project was primarily built to be used as a standalone CLI tool. 
> **Running `gbounty` as a service may pose security risks.** 
> It's recommended to use with caution and additional security measures.

# Getting started 

## Install GBounty

To start using GBounty, you can either install it using [Go](https://go.dev/), or download one of the pre-compiled 
binaries from [GitHub Releases](https://github.com/BountySecurity/gbounty/releases).

### Installation with Go

GBounty requires **Go v1.21** to install successfully. Run the following command to install the latest 
version under development:

```sh
go install -v github.com/bountysecurity/gbounty/cmd/gbounty@main
```

### Installation with GitHub Releases

Navigate to the [GitHub Releases page](https://github.com/BountySecurity/gbounty/releases) and download the pre-compiled
binary of the latest version (or any other) for the operating system (Linux, macOS, or Windows) and architecture 
(amd64, arm64, 386...) of your preference.

### Other installation mechanism

Unfortunately, currently we don't have support for other installation mechanisms, like [Homebrew](https://brew.sh/),
[Snap](https://snapcraft.io/), [Choco](https://chocolatey.org/) or [Docker](https://www.docker.com/), but contributions
are welcome! _See [#1](https://github.com/BountySecurity/gbounty/issues/1), for instance._

<br/>
<br/>
<br/>


Please, consider exploring the following comparable open-source projects that might also be beneficial for you:

[FFuF](https://github.com/ffuf/ffuf), [Jaeles](https://github.com/jaeles-project/jaeles),
[Nuclei](https://github.com/projectdiscovery/nuclei), [Qsfuzz](https://github.com/ameenmaali/qsfuzz),
[Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster),
[Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates),
[Google tsunami](https://github.com/google/tsunami-security-scanner),
and [ChopChop](https://github.com/michelin/ChopChop).

### License

GBounty is distributed under [MIT License](./LICENSE)
