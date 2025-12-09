---
title: "Understanding and creating polyglots files"
date: 2025-12-08 00:00:00 +0800
categories: [File Upload, Polyglots]
author: "Felipe Raczkowski Anaya"
---

The goal of this post is to explore the nature of polyglot files and the scenarios where they are most effective for discovering vulnerabilities. We will also explore two existing tools which are going to help us create this kind of files.

Knowing the basics and how to use tools is valuable. However I firmly believe that taking that extra step to thoroughly understand the underlying mechanics, what they are actually doing and why, leads to a much deeper comprehension of any topic. This is exactly why I wanted to break this topic down step by step and with as much detail as possible.

# Polyglot Files

Starting with the main concept, these files are created by carefully structuring data so that different parsers interpret the same file differently. For example, a .png image might contain a hidden .exe payload, allowing it to behave as either an image or an executable depending on the context. This technique is commonly seen in malware distribution, but it's also useful for bypassing file upload filters or exploiting weaknesses in file parsers.

Take a PNG file, for instance. It normally starts with its own file headers/signature. The idea is to inject the signature or opening tags of a different file type like HTML somewhere inside it without corrupting the image.

## <u>Scenarios where testing polyglot file uploads is worth it</u>

Testing for polyglot file uploads is worth it in scenarios where the server processes uploaded files in multiple ways or passes them through different components. This includes:

- When an uploaded image or PDF is handled by image processing libraries or document parsers (CVE-2016-3714)

- When the metadata contained in a file is processed or manipulated by the server after the upload (CVE-2021-22204)

- When the file and, as a consequence, its extension can be modified after it has been uploaded (CVE-2025-34085)

- When the server performs any transformation of the file after being uploaded, such as resizing, converting images, or compression/decompression of any kind of file. These may accidentally execute embedded code or perform undesirable actions (CVE-2024-34790)

Even though we don't know exactly what's happening on the server side, it wouldn't be worth testing this if we're just uploading a file and can't open or use it afterward.

## <u>Examples and Useful tools to create polyglot files</u>
### <u>Mitra</u>

This tool automates the creation of polyglot files. It detects the two formats being combined, analyzes their structure and magic bytes, and identifies the chunks or segments each format allows. Based on that, it generates combinations where both formats can coexist within a single file. The tool supports the creation of these four categories of polyglots:

1. **Stacks**: Simply appends one file after the other. Each parser reads only the part it recognizes and ignores the rest.

2. **Parasites**: Injects file 2 into a location inside file 1 that allows arbitrary data without breaking its structure. This works if file1 has flexible or unused chunks.

3. **Zippers**: Builds a file that is valid for both parsers simultaneously. It is created by overlapping the structures of file 1 and file 2, effectively “zipping” both formats together. The result is a more complex structure compared to parasite files.

4. **Cavities**: Leverages “empty” or unused spaces within the primary file format to inject content from a second format. These spaces don't affect the validity of the original file and can be used to hide or embed payloads.

As an example, we are going to create a PNG file which has an HTML embedded inside.

After executing Mitra, it shows that it was possible to create 2 types of combinations, a **stack** and a **parasite** file.

![Primera imagen](/assets/img/Polyglot-Post/image1.png)

By inspecting the **parasite** file, it embedded the HTML file inside the PNG without corrupting it, using a “cOMM” chunk.

![Segunda imagen](/assets/img/Polyglot-Post/image2.png)

Let's dive into why Mitra created this file the way it did, and why it can behave in two completely different ways just by changing its extension.

According to the official PNG specification (RFC 2083), we know that this “cOMM” chunk is considered ancillary because its first character is lowercase (‘c’), which sets the ancillary bit to 1 [3.3 – Chunk Naming Conventions - Page 13](https://datatracker.ietf.org/doc/html/rfc2083). Mitra simply took advantage of this and injected the payload inside this chunk.

Ancillary chunks are blocks of data whose contents are not strictly required to reconstruct or display the main image, and they can hold additional information while still keeping a valid PNG format [4.2 – Ancillary Chunks - Page 19](https://datatracker.ietf.org/doc/html/rfc2083)

But here’s the interesting part: the “cOMM" chunk used here is not one of the officially defined ancillaries in the RFC.

So… what’s going on here???

This is where the magic happens: since “cOMM” is not part of the standard PNG specification, decoders will safely ignore any unknown ancillary chunk types and continue rendering the image normally [12.12 – Chunk Layout - Page 77](https://datatracker.ietf.org/doc/html/rfc2083)

This behavior makes it possible to embed additional data such as an entire HTML file inside such a chunk without affecting how the image is rendered. As a result, the PNG remains visually intact, but it secretly carries an extra payload that may be interpreted differently depending on how the file is served or processed.

In contrast, if this polyglot is instead opened with a .html extension, the browser will interpret the valid HTML tags and render the content, executing the JavaScript code as demonstrated in the image below.

![Tercera imagen](/assets/img/Polyglot-Post/image3.png)

Moving on to the stack file, it simply concatenated both files.

![Cuarta imagen](/assets/img/Polyglot-Post/image4.png)


We can also do this by just executing: `echo "<script>alert(‘XSS via polyglot!’)</script>" >> base.png`

Since we’re forging a .png, the server would treat the file as an actual image. This becomes useful if the target application has image viewers that render the file or parse the image using vulnerable libraries or components.

Recently, I showed two files that could coexist, but now I want to go in the opposite direction.

I will show an example where two files are incompatible. This usually happens when one of the files strictly requires its signature to be located at the very beginning of the document, or precisely at offset 0x00, as it is the case with PNG files.

So, let’s see what happens when we try to create a PDF with a PNG file embedded inside. The result is the following:

![Quinta imagen](/assets/img/Polyglot-Post/image5.png)


In this case, Mitra indicates that the PDF can indeed embed another file starting at offset 0x30, which means right after the signature and inside of an object. However, this is incompatible with PNGs, as this kind of files must strictly start at offset 0x00. You can think of it as the stricter file type defining the main structure and core of the polyglot, while the more flexible one (in this case, the PDF) is adjusted to fit within that structure. So what would actually be possible is creating a PNG that contains a PDF file inside, not the other way around.

Furthermore, if instead of attaching a PNG we use a simple .sh file, we can see that the payload is successfully injected inside the first PDF object at the specified offset.

![Sexta imagen](/assets/img/Polyglot-Post/image6.png)


By showing these examples we can conclude that any kind of combination fully depends on how flexible the formats are when being combined, from where the signature is required to be located, to which chunks can be used.

**Github**: https://github.com/corkami/mitra

### <u>ExifTool</u>

There are specific scenarios where ExifTool becomes highly useful, particularly when the attack vector involves server-side manipulation of file metadata.

Consider the case of a file upload feature that only validates the .png magic bytes of the file but allows arbitrary extensions.

We could craft a PNG file (with valid magic bytes) but rename it to .php or .jsp and when uploaded, the server might interpret it as an executable (PHP/JSP) rather than an image.

Examples:
1. `<%= System.getProperty("java.version") %>`
2. `<?php echo phpversion(); ?>`

![Septima imagen](/assets/img/Polyglot-Post/image7.png)


In this example we have a valid png structure and an embedded jsp payload in the file metadata.

Depending on what we are trying to exploit, we may obtain different outputs. If the metadata is displayed in the user interface, it is more likely that we will observe an XSS. On the other hand, if we embed a payload inside an image with the goal of extracting the PHP engine version, the response is more likely to appear in the server response when we request the path of the uploaded image. This is why being able to directly access the uploaded file is important in order to exploit these kinds of scenarios.

**Github**: https://github.com/exiftool/exiftool



## <u>MIME sniffing</u>

When manipulating files, there’s an important concept to consider:  MIME sniffing.

This occurs on the browser when, instead of trusting the Content-Type header provided by the server, it attempts to guess the file type by inspecting the magic bytes.

If we manage to upload a .png file (because only the extension is being validated) but the browser performs MIME sniffing, we could exploit this by crafting a .png whose initial content matches the signatures that browsers identify as HTML/JavaScript during MIME sniffing. This tricks the browser into interpreting our .png as HTML.

Depending on how the browser handles MIME sniffing, sometimes the content or magic bytes of the embedded file must appear at the beginning, which breaks the structure of the valid .png. In such cases, the file would no longer qualify as a polyglot.

This exploitation could lead to XSS vulnerabilities and is only possible if the server lacks the **X-Content-Type-Options: nosniff** header. Nowadays, some servers include this header by default, and modern browsers restrict MIME sniffing. However, it’s always worth verifying whether the mentioned header is enforced.


## <u>Remediation for Polyglot Files</u>

An effective remediation to prevent this type of attacks is implementing a **Content Disarm and Reconstruction (CDR)**. This technology is excellent for prevention of file-based attacks. Instead of trying to detect malicious content, with this method it is assumed that everything inside the file is potentially dangerous and a specific sanitization is carried out.

Three steps take place when a file is processed by a CDR. First, the file is disassembled into its core elements (headers, chunks, metadata, comments), and then only the components and attributes required for the legitimate functionality of the file are preserved. You can think of this technology as having a whitelist of which components make up a legitimate PDF. Anything that does not match is removed. Finally, the file is reconstructed using only the components that passed the filter.


## <u>Conclusion</u>

In conclusion, these are some of the key methods for crafting polyglot files and leveraging them when server-side processing is detected post-upload. Just to briefly recap, exploitation opportunities may arise through:
- Metadata parsers 
- Image processors 
- Vulnerable libraries handling file content
- Web server misconfigurations that improperly execute uploaded files

This approach becomes particularly effective when file validation fails to properly verify both extensions and actual content signatures.

Finally, I would like to acknowledge Ange Albertini, creator of the Mitra tool, and Phil Harvey, creator of ExifTool, for making such interesting resources available to the community. These tools inspired me to dive deeper into this topic and I highly encourage exploring their work.
