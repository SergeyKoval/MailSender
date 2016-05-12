Send email tester
=================
To use this tester:

* install this project with maven
* place `the mail-tester-jar-with-dependencies.jar` near the `MailConfig.xml` and `MailConfig.xsd` files
* run `.jar` file with `java -jar the mail-tester-jar-with-dependencies.jar` with 3 params:
    - receiver email
    - mail sender identifier (from `MailConfig.xml` config file)
    - *code* parameter
