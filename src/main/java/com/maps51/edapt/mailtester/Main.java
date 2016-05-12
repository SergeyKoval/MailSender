package com.maps51.edapt.mailtester;

import com.maps51.edapt.common.configuration.manager.BaseConfigurationManager;
import com.maps51.edapt.common.configuration.manager.ConfigurationManager;
import com.maps51.edapt.common.configuration.parser.ConfigurationParser;
import com.maps51.edapt.common.configuration.parser.XmlConfigurationParser;
import com.maps51.edapt.common.mail.exception.MissedMailConfigurationException;
import com.maps51.edapt.common.mail.model.configuration.AuthenticationConfig;
import com.maps51.edapt.common.mail.model.configuration.MailConfig;
import com.maps51.edapt.common.mail.model.configuration.MailsConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.io.FileNotFoundException;
import java.util.Properties;

public class Main {
    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    private static final String ENABLE_START_TLS_PROPERTY = "mail.smtp.starttls.enable";
    private static final String HOST_PROPERTY = "mail.smtp.host";
    private static final String USER_PROPERTY = "mail.smtp.user";
    private static final String SEND_PARTIAL_PROPERTY = "mail.smtp.sendpartial";
    private static final String PORT_PROPERTY = "mail.smtp.port";
    private static final String SOCKET_FACTORY_PORT_PROPERTY = "mail.smtp.socketFactory.port";
    private static final String SOCKET_FACTORY_CLASS_PROPERTY = "mail.smtp.socketFactory.class";
    private static final String AUTH_PROPERTY = "mail.smtp.auth";
    private static final String SSL_SOCKET_FACTORY = "javax.net.ssl.SSLSocketFactory";
    private static final String SSL_TRUST_PROPERTY = "mail.smtp.ssl.trust";
    private static final String CODE_PARAMETER = "${code}";

    public static void main(String[] args) {
        LOG.info("========= STARTING SEND EMAIL TEST WITH PARAMS: {} =========", (Object) args);
        try {
            Address receiverAddress = getReceiverParameter(args);
            String senderIdentifier = getSenderIdentifierParameter(args);
            String code = getCodeParameter(args);

            MailConfig mailConfiguration = getConfig(senderIdentifier);
            Properties properties = buildProperties(mailConfiguration);
            LOG.info("Getting session instance...");
            Session session = Session.getInstance(properties);

            LOG.info("Starting message construction...");
            MimeMessage simpleMessage = new MimeMessage(session);
            LOG.info("\tSetting sender...");
            simpleMessage.setFrom(new InternetAddress(mailConfiguration.getEmail(), mailConfiguration.getSenderName()));
            LOG.info("\tSetting receiver...");
            simpleMessage.addRecipient(Message.RecipientType.TO, receiverAddress);
            LOG.info("\tSetting subject...");
            simpleMessage.setSubject(mailConfiguration.getSubject());
            LOG.info("\tSetting content...");
            simpleMessage.setContent(prepareBody(mailConfiguration.getBody(), code), mailConfiguration.getContentType());

            LOG.info("Starting transport construction...");
            Transport transport = session.getTransport(mailConfiguration.getTransport());
            LOG.info("Filling authentication parameters...");
            AuthenticationConfig authenticationConfig = mailConfiguration.getAuthenticationConfig();
            if (authenticationConfig != null) {
                LOG.info("\tUsing provided username and password.");
                transport.connect(authenticationConfig.getUsername(), authenticationConfig.getPassword());
            } else {
                LOG.warn("\tNo authentication provided.");
                transport.connect();
            }
            LOG.info("Sending message...");
            transport.sendMessage(simpleMessage, simpleMessage.getAllRecipients());
            LOG.info("Message successfully sent. Closing transport.");
            transport.close();
            LOG.info("Transport closed.");

        } catch (Exception e) {
            LOG.error("Something went wrong.", e);
        }
    }

    private static Address getReceiverParameter(String[] args) {
        LOG.info("Extracting receiver address from command line parameters (1st parameter)...");
        try {
            InternetAddress internetAddress = new InternetAddress(args[0]);
            internetAddress.validate();
            LOG.info("Receiver: {}", internetAddress);
            return internetAddress;
        } catch (IndexOutOfBoundsException e) {
            throw new IllegalArgumentException("Receiver address, which should be passed as the 1st parameter, is missing.", e);
        } catch (AddressException e) {
            throw new IllegalArgumentException("Passed address parsing failed.", e);
        }
    }

    private static String getSenderIdentifierParameter(String[] args) {
        LOG.info("Extracting sender identifier parameter from command line parameters (2nd parameter)...");
        try {
            String senderIdentifier = args[1];
            LOG.info("Sender identifier: {}", senderIdentifier);
            return senderIdentifier;
        } catch (IndexOutOfBoundsException e) {
            throw new IllegalArgumentException("Sender identifier, which should be passed as the 2nd parameter, is missing.", e);
        }
    }

    private static String getCodeParameter(String[] args) {
        LOG.info("Extracting code parameter from command line parameters (3rd parameter)...");
        try {
            String code = args[2];
            LOG.info("Code: {}", code);
            return code;
        } catch (IndexOutOfBoundsException e) {
            throw new IllegalArgumentException("Code to send, which should be passed as the 3rd parameter, is missing.", e);
        }
    }

    private static MailConfig getConfig(String mailConfigIdentifier) throws FileNotFoundException {
        try {
            LOG.info("Parsing configuration...");
            Resource resource = new FileSystemResource("MailConfig.xsd");
            ConfigurationParser parser = new XmlConfigurationParser(resource, MailsConfiguration.class);
            ConfigurationManager<MailsConfiguration> mailsConfigurationManager =
                    new BaseConfigurationManager<>("MailConfig.xml", parser, MailsConfiguration.class);
            LOG.info("Configuration successfully parsed.");
            LOG.info("Getting config with identifier: ", mailConfigIdentifier);
            return mailsConfigurationManager.getConfiguration().getMailConfig(mailConfigIdentifier);
        } catch (FileNotFoundException e) {
            throw new IllegalStateException("Error parsing configuration.", e);
        } catch (MissedMailConfigurationException e) {
            throw new IllegalArgumentException("Error getting configuration.", e);
        }
    }

    private static Properties buildProperties(MailConfig mailConfig) {
        LOG.info("Building properties for email sending...");
        Properties properties = System.getProperties();
        buildSecurityProperties(mailConfig, properties);
        properties.put(HOST_PROPERTY, mailConfig.getHost());
        properties.put(PORT_PROPERTY, mailConfig.getPort());
        properties.put(USER_PROPERTY, mailConfig.getEmail());
        properties.put(SEND_PARTIAL_PROPERTY, mailConfig.getSendPartial());
        LOG.info("Properties built successfully.");

        return properties;
    }

    private static void buildSecurityProperties(MailConfig mailConfig, Properties properties) {
        LOG.info("Building security properties for email sending...");
        AuthenticationConfig configuredAuthentication = mailConfig.getAuthenticationConfig();
        if (configuredAuthentication != null && configuredAuthentication.isStartTls()) {
            properties.put(SSL_TRUST_PROPERTY, configuredAuthentication.getSslTrustedHosts());
            properties.put(ENABLE_START_TLS_PROPERTY, Boolean.TRUE);
        } else {
            properties.put(SOCKET_FACTORY_PORT_PROPERTY, mailConfig.getPort());
            properties.put(SOCKET_FACTORY_CLASS_PROPERTY, SSL_SOCKET_FACTORY);
        }
        properties.put(AUTH_PROPERTY, configuredAuthentication != null);
    }

    private static String prepareBody(String data, String codeParameter) {
        return StringUtils.replace(data, CODE_PARAMETER, codeParameter);
    }
}
