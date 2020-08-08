# ZP Proj

This school project was created for the [ZP (Zastita podataka, en. Data Protection) course][zp], 
which is part of the Bachelor's studies at the [School of Electrical Engineering][school], [University of Belgrade][uni].

This project consisted the backend implementation of a desktop app for parsing, creating and signing X509 certificates, and was implemented in Java using the [BouncyCastle library][bouncycastle]. 
The main goal was to successfully establish an SSL connection using one of the certificates issued by the application.
The main functionality is located in the [MyCode][mycode] class, which implements the required  `CodeV3` interface.

The [initial project statement][statement] along with the appendixes (all in Serbian) is given in the `docs` folder.

[zp]: http://rti.etf.bg.ac.rs/rti/ir4zp/index.html
[school]: https://www.etf.bg.ac.rs/
[uni]: https://www.bg.ac.rs/
[bouncycastle]: https://www.bouncycastle.org/
[mycode]: ./ZP%20Projekat/src/implementation/MyCode.java
[statement]: ./docs/projekat%202017.pdf
