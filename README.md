<h1 align="center">
  <br>
  <a style="background: #215071; border: 10px solid #215071;" href="https://gbounty.net/">
        <img style="background: #215071;" src="static/gbounty-logo.png" width="200px" alt="GBounty">
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
vulnerability templates contributed by **dozens** of security researchers and engineers.

| :exclamation:  **Disclaimer**                                                                                                                                                                            |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **This project is in active development**. Expect breaking changes with releases. Review the release changelog before updating.                                                                          |
| This project was primarily built to be used as a standalone CLI tool. **Running `gbounty` as a service may pose security risks.** It's recommended to use with caution and additional security measures. |

# Install GBounty

GBounty requires **go1.22** to install successfully. Run the following command to install the latest version -

```sh
go install -v github.com/bountysecurity/gbounty/cmd/gbounty@latest
```
