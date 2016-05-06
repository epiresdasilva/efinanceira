package br.com.evandropires.efinanceira;


import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CertificadoBean {

	private PrivateKey privateKey;
	private X509Certificate certificate;

	public CertificadoBean(PrivateKey privateKey, X509Certificate certificate) {
		super();
		this.privateKey = privateKey;
		this.certificate = certificate;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}

}
