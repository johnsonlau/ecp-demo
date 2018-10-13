package com.example.ecpdemo;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.ssl.SSLContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.integration.xml.xpath.XPathUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;


@Component
public class EcpRunner implements CommandLineRunner {

   private final static Logger LOGGER = LoggerFactory.getLogger(EcpRunner.class);

   private final static String FAULT_DOCUMENT = "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
         "               <S:Body>\n" +
         "                 <S:Fault>\n" +
         "                    <faultcode>S:Server</faultcode>\n" +
         "   <faultstring>responseConsumerURL from SP and assertionConsumerServiceURL from IdP do not match</faultstring>\n" +
         "                 </S:Fault>\n" +
         "               </S:Body>\n" +
         "            </S:Envelope>";

   @Value("${proxy.server:#{null}}")
   private String proxyServer;

   @Value("${idp.server:#{null}}")
   private String idpEcpEndpoint;

   @Value("${keystone.endpoint:#{null}}")
   private String keystoneEndpoint;

   @Value("${username:#{null}}")
   private String username;

   @Value("${password:#{null}}")
   private String password;

   private Node relayState;

   private String responseConsumerURL;

   @Override
   public void run(String... args) throws Exception {
      RestTemplate restTemplate = new RestTemplate();

      SSLContextBuilder builder = new SSLContextBuilder();
      builder.loadTrustMaterial(null, new TrustAllStrategy());
      SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            builder.build(), new NoopHostnameVerifier());
      HttpClientBuilder httpClientBuilder = HttpClientBuilder.create().setSSLSocketFactory(sslsf);
      if (this.proxyServer != null) {
         HttpHost proxy = HttpHost.create(proxyServer);
         httpClientBuilder.setRoutePlanner(new DefaultProxyRoutePlanner(proxy));
      }

      restTemplate.setRequestFactory(
            new HttpComponentsClientHttpRequestFactory(httpClientBuilder.build()));

      if (idpEcpEndpoint == null || keystoneEndpoint == null) {
         return;
      }

      ResponseEntity<String> spResp = spRequest(restTemplate);
      ResponseEntity<String> ecpResp = authenticate(restTemplate, spResp);
      Document ecpDoc = xmlFromString(ecpResp.getBody());
      if (!isValidResponse(ecpDoc)) {
         postFault(restTemplate, ecpDoc);
         return;
      }

      ResponseEntity<String> keystoneResp = postResp(restTemplate, ecpResp);
      LOGGER.info("Keystone token {}", keystoneResp.getHeaders().get("X-Subject-Token").get(0));
   }

   private ResponseEntity<String> spRequest(RestTemplate restTemplate) throws Exception {
      HttpHeaders headers = new HttpHeaders();
      headers.add("Accept",
            "text/html; application/vnd.paos+xml");
      headers.add("PAOS",
            "ver=\"urn:liberty:paos:2003-08\";\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"");
      ResponseEntity<String> resp = restTemplate.exchange(keystoneEndpoint,
            HttpMethod.GET,
            new HttpEntity<String>(headers),
            String.class);
      LOGGER.debug("###### BEGIN SP RESPONSE");
      LOGGER.debug("{}", resp.getBody());
      LOGGER.debug("###### END SP RESPONSE");

      relayState = XPathUtils.evaluate(resp.getBody(),
            "/*[local-name()='Envelope']/*[local-name()='Header']/*[local-name()='RelayState']",
            "node");
      responseConsumerURL = XPathUtils.evaluate(
            resp.getBody(),
            "/*[local-name()='Envelope']/*[local-name()='Header']/*[local-name()='Request']/@responseConsumerURL");
      return resp;
   }

   private Document xmlFromString(String s) throws ParserConfigurationException, IOException, SAXException {
      DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = builderFactory.newDocumentBuilder();
      InputSource is = new InputSource(new StringReader(s));
      return builder.parse(is);
   }

   private String stringFromXml(Document doc) throws TransformerException {
      TransformerFactory tf = TransformerFactory.newInstance();
      Transformer transformer = tf.newTransformer();
      transformer.setOutputProperty(OutputKeys.INDENT, "no");
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
      StringWriter writer = new StringWriter();
      transformer.transform(new DOMSource(doc), new StreamResult(writer));
      return writer.toString();
   }

   private ResponseEntity<String> authenticate(RestTemplate restTemplate,
         ResponseEntity<String> spResp) throws Exception {
      Document doc = xmlFromString(spResp.getBody());
      Node headerNode = getSamlHeader(doc);
      headerNode.getParentNode().removeChild(headerNode);

      String idpRequest = stringFromXml(doc);

      HttpHeaders headers = new HttpHeaders();
      headers.add("Content-Type", "test/xml; charset=utf-8");
      headers.add("Authorization", "Basic " +
            Base64.encodeBase64String(String.format("%s:%s", username, password).getBytes("utf-8")));
      LOGGER.debug("###### BEGIN IDP REQUEST");
      LOGGER.debug("{}", idpRequest);
      LOGGER.debug("###### END IDP REQUEST");
      ResponseEntity<String> resp = restTemplate.exchange(idpEcpEndpoint,
            HttpMethod.POST,
            new HttpEntity<>(idpRequest, headers),
            String.class);
      LOGGER.debug("###### BEGIN IDP RESPONSE");
      LOGGER.debug("{}", resp.getBody());
      LOGGER.debug("###### END IDP RESPONSE");
      return resp;
   }

   private boolean isValidResponse(Document doc) {
      String assertionConsumerService = getAssertionConsumerServiceURL(doc);
      return responseConsumerURL.equals(assertionConsumerService);
   }

   private Node getSamlHeader(Document doc) {
      return XPathUtils.evaluate(doc,
            "/*[local-name()='Envelope']/*[local-name()='Header']",
            "node");
   }

   private String getAssertionConsumerServiceURL(Document doc) {
      Node header = getSamlHeader(doc);
      return XPathUtils.evaluate(
            header,
            "*[local-name()='Response']/@AssertionConsumerServiceURL");
   }

   private void postFault(RestTemplate restTemplate, Document ecpDoc) {
      String assertionConsumerService = getAssertionConsumerServiceURL(ecpDoc);
      LOGGER.error("assertionConsumerServiceURL {} does not match responseConsumerURL {}.",
            assertionConsumerService, responseConsumerURL);
      HttpHeaders headers = new HttpHeaders();
      headers.add("Content-Type", "application/vnd.paos+xml");
      ResponseEntity<String> resp = restTemplate.exchange(responseConsumerURL,
            HttpMethod.POST,
            new HttpEntity<>(FAULT_DOCUMENT, headers),
            String.class);
      LOGGER.debug("###### BEGIN SP RESPONSE");
      LOGGER.debug("{}", resp.getBody());
      LOGGER.debug("###### END SP RESPONSE");
   }

   private ResponseEntity<String> postResp(RestTemplate restTemplate, ResponseEntity<String> ecpResp) throws Exception {
      Document doc = xmlFromString(ecpResp.getBody());
      Node headerNode = getSamlHeader(doc);
      Node newRelayState = relayState.cloneNode(true);
      doc.adoptNode(newRelayState);
      Node responseNode = XPathUtils.evaluate(
            headerNode,
            "*[local-name()='Response']",
            "node");
      headerNode.replaceChild(newRelayState, responseNode);

      String spRequest = stringFromXml(doc);
      LOGGER.debug("###### BEGIN SP REQUEST");
      LOGGER.debug("{}", spRequest);
      LOGGER.debug("###### END SP REQUEST");

      HttpHeaders headers = new HttpHeaders();
      headers.add("Content-Type", "application/vnd.paos+xml");
      ResponseEntity<String> resp = restTemplate.exchange(responseConsumerURL,
            HttpMethod.POST,
            new HttpEntity<>(spRequest, headers),
            String.class);
      LOGGER.debug("###### BEGIN SP RESPONSE");
      LOGGER.debug("{}", resp.getBody());
      LOGGER.debug("###### END SP RESPONSE");

      resp = restTemplate.exchange(keystoneEndpoint,
            HttpMethod.GET,
            new HttpEntity<String>(headers),
            String.class);
      return resp;
   }

}
