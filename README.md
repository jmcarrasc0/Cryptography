# [Jmcarrasc0 - Mail.Sending](https://www.patreon.com/join/jmcarrasc0?)

<a href="https://www.patreon.com/join/jmcarrasc0?"><img src="https://i.postimg.cc/hPcgmRWQ/jmcarrasc0-logo.png" alt="jmcarrasco logo" ></a>

**Mail.Sending** is a nuget package based on **.NET** for sending mail through an Smtp server with the SMTP Relay function or with user and password authentication..


## Quick install

Mail.Sending is constantly in development! Try it out now:

### NuGet

```sh
PM> Install-Package Jmcarrasc0.Mail.Sending -Version 1.1.1
```

**or**

### .NET CLI

```sh
> dotnet add package Jmcarrasc0.Mail.Sending --version 1.1.1
```

### PackageReference

```sh
<PackageReference Include="Jmcarrasc0.Mail.Sending" Version="1.1.1" />
```
### Paket CLI

```sh
> paket add Jmcarrasc0.Mail.Sending --version 1.1.1
```

### Script & Interactive

```sh
> #r "nuget: Jmcarrasc0.Mail.Sending, 1.1.1"
```

### Cake

```sh
// Install Jmcarrasc0.Mail.Sending as a Cake Addin
#addin nuget:?package=Jmcarrasc0.Mail.Sending&version=1.1.1

// Install Jmcarrasc0.Mail.Sending as a Cake Tool
#tool nuget:?package=Jmcarrasc0.Mail.Sending&version=1.1.1
```

<br>
<br>

# How to use it

It is very easy to implement

## C#

```c#

using Jmcarrasc0.Mail.Sending;

var mail = new Mail();

    var email = new Email()
    {
        Account = "Account or user",
        Password = "Password",
        MailServer = "Server",
        IsSSL = "true or false",
        Port = "Default communication port 25",
        Addressees = new List<Addressee>() {
            new Addressee {
                ShowName = "ShowName",
                Mail = "correo@demo.com",
            }
        },
        AddresseesCC = new List<Addressee>() {
            new Addressee {
                ShowName = "ShowName",
                Mail = "correo@demo.com",
            }
        },
        AddresseesBCC = new List<Addressee>() {
            new Addressee {
                ShowName = "ShowName",
                Mail = "correo@demo.com",
            }
        },
        BodyIsHtml = "true or false",
        Body = "Read your HTML structure",
        ScreenName = "Name to Display",
        Title = "Title",
        Attachments = new List<Attached>() {
            new Attachments {
                file="Binary file",
                name="Name",
                MediaType="Media type" 
            }
        }
        
    };

    _ = mail.SendMail(email);


/// <summary>
/// Function for sending e-mails through SMTP Relay
/// </summary>


var mail = new Mail();

    var email = new EmailHost()
    {
        Host = "Server",
        IsSSL = "true or false",
        From= "From Email",
        Port = "Default communication port 25",
        Addressees = new List<Addressee>() {
            new Addressee {
                ShowName = "ShowName",
                Mail = "correo@demo.com",
            }
        },
        AddresseesCC = new List<Receiver>() {
            new Addressee {
                ShowName = "ShowName",
                Mail = "correo@demo.com",
            }
        },
        AddresseesBCC = new List<Addressee>() {
            new Addressee {
                ShowName = "ShowName",
                Mail = "correo@demo.com",
            }
        },
        BodyIsHtml = "true or false",
        Body = "Read your HTML structure",
        ScreenName = "Name to Display",
        Title = "Title",
        Attachments = new List<Attached>() {
            new Attachments {
                file="Binary file",
                name="Name",
                MediaType="Media type" 
            }
        }
        
    };

   _ = mail.SendMailbyHost(email);



```


<br>
<br>

## VB.NET

```vb

Imports Jmcarrasc0.Mail.Sending

        Dim mail = New Mail()
        Dim email = New Email() With {
            .Account = "Account or user",
            .Password = "Password",
            .MailServer = "Server",
            .IsSSL = "true or false",
            .Port = "Default communication port 25",
            .Recipients = New Recipient List(From Recipients)() From {
                New Recipient() With {
                    .ShowName = "Show Name",
                    .Mail = "correo@demo.com"
                }
            },
            .AddresseesCC = New List(Of Addressee)() From {
                New Addressee() With {
                    .ShowName = "ShowName",
                    .Mail = "correo@demo.com"
                }
            },
            .AddresseesBCC = New List(Of Addressee)() From {
                New Addressee() With {
                    .ShowName = "ShowName",
                    .Mail = "correo@demo.com"
                }
            },
            .BodyIsHtml = "true or false",
            .Body = "Read your HTML structure",
            .ScreenName = "Name to Display",
            .Title = "Title",
            .Attachments = New List(Of Attached)() From {
                New Attachment() With {
                    .file = "Binary File",
                    .name = "Name",
                    .MediaType = "Media Type"
                }
            }
        }
        Dim result = mail.SendMail(email)


'Function for sending e-mails through SMTP Relay'


        Dim mail = New Mail()
        Dim email = New EmailHost() With {
            .Host = "Server",
            .IsSSL = "true or false",
            .Port = "Default communication port 25",
            .Recipients = New Recipient List(From Recipients)() From {
                New Recipient() With {
                    .ShowName = "Show Name",
                    .Mail = "correo@demo.com"
                }
            },
            .AddresseesCC = New List(Of Addressee)() From {
                New Addressee() With {
                    .ShowName = "ShowName",
                    .Mail = "correo@demo.com"
                }
            },
            .AddresseesBCC = New List(Of Addressee)() From {
                New Addressee() With {
                    .ShowName = "ShowName",
                    .Mail = "correo@demo.com"
                }
            },
            .BodyIsHtml = "true or false",
            .Body = "Read your HTML structure",
            .ScreenName = "Name to Display",
            .Title = "Title",
            .Attachments = New List(Of Attached)() From {
                New Attachment() With {
                    .file = "Binary File",
                    .name = "Name",
                    .MediaType = "Media Type"
                }
            }
        }
        Dim result = mail.SendMailbyHost(email)
        
```

<br>
<br>

## Compatibily Support

**Mail.Sending** is a nuget package compatible with the following Frameworks

- .NET 6
- .NET 5
- .NET Core 3.1


<br>
<br>




## Copyright and license ![Github](https://img.shields.io/github/license/jmcarrasc0/Mail.Sending)

Code copyright 2022 Juan Carrasco. Code released under [the MIT license](https://github.com/jmcarrasc0/Mail.Sending/blob/master/LICENSE).
