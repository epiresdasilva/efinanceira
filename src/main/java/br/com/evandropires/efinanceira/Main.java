package br.com.evandropires.efinanceira;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.net.ssl.HttpsURLConnection;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class Main {

	private Main() {
	}

	public static Main newInstance() {
		return new Main();
	}

	public static void main(String[] args) throws Exception {
		Main.newInstance().execute();
	}

	public void execute() throws Exception {
		CertificadoBean certificadoBean = getCertificadoBean();

		InputStream inputStream = Main.class
				.getResourceAsStream("/evtCadDeclarante.xml");

		String elementName = "evtCadDeclarante";

		Document document = documentFactory(inputStream);
		Element element = (Element) document.getElementsByTagName(elementName)
				.item(0);
		element.setIdAttribute("id", true);

		String xmlSigned = signXML(document, element.getParentNode(),
				elementName, certificadoBean);
		System.out.println("EVENTO ASSINADO | " + xmlSigned);

		sendXML(xmlSigned, certificadoBean);
	}

	private void sendXML(String xml, CertificadoBean certificadoBean)
			throws Exception {
		xml = xml.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");
		System.out.println("RESPONSE | "
				+ sendSoapEnvelope(certificadoBean, xml));
	}

	private CertificadoBean getCertificadoBean() throws KeyStoreException,
			NoSuchProviderException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException, IOException,
			UnrecoverableEntryException {
		String certificatePath = "PATH/certificado.pfx";
		String certificatePassword = "1234";

		KeyStore ksCertificado = KeyStore.getInstance("pkcs12", "SunJSSE");
		ksCertificado.load(new FileInputStream(new File(certificatePath)),
				certificatePassword.toCharArray());

		CertificadoBean certificadoBean = null;
		Enumeration<String> aliases = ksCertificado.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			X509Certificate cert = (X509Certificate) ksCertificado
					.getCertificate(alias);

			KeyStore.PrivateKeyEntry pkEntry = null;
			PrivateKey privateKey = null;
			if (ksCertificado.isKeyEntry(alias)) {
				pkEntry = (KeyStore.PrivateKeyEntry) ksCertificado.getEntry(
						alias, new KeyStore.PasswordProtection(
								certificatePassword.toCharArray()));
				privateKey = pkEntry.getPrivateKey();
			}

			certificadoBean = new CertificadoBean(privateKey, cert);
			break;
		}

		return certificadoBean;
	}

	private String signXML(Document document, Node toSign, String elementName,
			CertificadoBean certificadoBean) throws Exception {
		Element elemento = (Element) document.getElementsByTagName(elementName)
				.item(0);
		elemento.setIdAttribute("id", true);
		String id = elemento.getAttribute("id");

		Init.init();

		ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "");
		XMLSignature sig = new XMLSignature(document, "",
				XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);

		toSign.appendChild(sig.getElement());

		{
			Transforms transforms = new Transforms(document);

			transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
			transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
			sig.addDocument("#" + id, transforms,
					"http://www.w3.org/2001/04/xmlenc#sha256");
		}

		trimWhitespace(document);

		{
			X509Certificate cert = certificadoBean.getCertificate();

			sig.addKeyInfo(cert);
			System.out.println("Start signing");
			sig.sign(certificadoBean.getPrivateKey());
			System.out.println("Finished signing");
		}

		return outputXML(document);
	}

	private String sendSoapEnvelope(CertificadoBean certificadoBean, String xml)
			throws Exception {
		HttpsURLConnection conn = null;
		try {
			String arquivoCacertsGeradoTodosOsEstados = "WORKSPACE/efinanceira/Cacerts";

			System.setProperty("javax.net.ssl.keyStore", "NONE");
			System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");
			System.setProperty("javax.net.ssl.keyStoreProvider", "SunJSSE");
			System.setProperty("javax.net.ssl.trustStoreType", "JKS");
			System.setProperty("javax.net.ssl.trustStore",
					arquivoCacertsGeradoTodosOsEstados);

			SocketFactoryDinamico socketFactoryDinamico = new SocketFactoryDinamico(
					certificadoBean.getCertificate(),
					certificadoBean.getPrivateKey());
			socketFactoryDinamico
					.setFileCacerts(arquivoCacertsGeradoTodosOsEstados);

			Protocol protocol = new Protocol("https", socketFactoryDinamico,
					443);
			Protocol.registerProtocol("https", protocol);

			URL url = new URL(
					"https://preprod-efinanc.receita.fazenda.gov.br/WsEFinanceira/WsRecepcao.asmx");

			conn = (HttpsURLConnection) url.openConnection();
			conn.setSSLSocketFactory(socketFactoryDinamico.getSSLContext()
					.getSocketFactory());
			conn.setDoOutput(true);
			conn.setRequestMethod("POST");
			conn.setRequestProperty("content-type", "text/xml");

			System.out.println("SOAP ENVELOPE | " + getEnvelope(xml));

			conn.getOutputStream().write(getEnvelope(xml).getBytes());
			conn.connect();

			if (conn.getResponseCode() == 200) {
				StringBuilder sb = new StringBuilder();
				BufferedReader reader = new BufferedReader(
						new InputStreamReader(conn.getInputStream()));
				while (reader.ready()) {
					sb.append(reader.readLine());
				}
				return sb.toString();
			} else {
				return "ERROR: " + conn.getResponseCode() + " | "
						+ conn.getResponseMessage();
			}
		} finally {
			if (conn != null) {
				conn.disconnect();
			}
		}
	}


	private String getEnvelope(String xml) {
		return "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap12:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\"><soap12:Header></soap12:Header><soap12:Body><loteEventos xmlns=\"http://sped.fazenda.gov.br/\"><eFinanceira xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"http://www.eFinanceira.gov.br/schemas/envioLoteEventos/v1_0_1\"><loteEventos><evento id=\"ID00\">"
				+ xml
				+ "</evento></loteEventos></eFinanceira></loteEventos></soap12:Body></soap12:Envelope>";
	}

	public static void trimWhitespace(Node node) {
		NodeList children = node.getChildNodes();
		for (int i = 0; i < children.getLength(); ++i) {
			Node child = children.item(i);
			if (child.getNodeType() == Node.TEXT_NODE) {
				child.setTextContent(child.getTextContent().trim());
			}
			trimWhitespace(child);
		}
	}

	private Document documentFactory(InputStream is) throws SAXException,
			IOException, ParserConfigurationException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		Document document = factory.newDocumentBuilder().parse(is);
		return document;
	}

	private String outputXML(Node doc) throws TransformerException {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		trans.transform(new DOMSource(doc), new StreamResult(os));
		String xml = os.toString();
		if ((xml != null) && (!"".equals(xml))) {
			xml = xml.replaceAll("\\r\\n", "");
			xml = xml.replaceAll(" standalone=\"no\"", "");
		}

		return xml;
	}

}
