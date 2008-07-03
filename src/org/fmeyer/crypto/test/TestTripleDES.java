package org.fmeyer.crypto.test;

/*
 * Copyright (c) 2006 Fernando Meyer
 * Author Fernando Meyer <fernando@fmeyer.org>
 * Java doc de referencia: http://java.sun.com/j2se/1.4.2/docs/api/javax/crypto/package-summary.html
 * Documentacao de referencia: http://en.wikipedia.org/wiki/Triple_DES
 */

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.fmeyer.crypto.TripleDES;

import junit.framework.TestCase;

public class TestTripleDES extends TestCase {

	private TripleDES localcript;
	private String texttocript;

	@Override
	protected void setUp() throws Exception {
		localcript = new TripleDES();

		texttocript = "Solvo Servicos de informatica";

		try {
			Cipher c = Cipher.getInstance("DESede");
			c.getAlgorithm();
		} catch (Exception e) {
			// se nao existir o algoritmo ele instala de um pacote maluco da sun
			Provider sunjce = new com.sun.crypto.provider.SunJCE();
			Security.addProvider(sunjce);
		}
	}

	/**
	 * Este metodo testa a criacao de uma chave e se este nao gerar exception o
	 * teste passou e a chave foi gerada
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	public void testCreateKey() throws NoSuchAlgorithmException {
		SecretKey key = localcript.generateKey();
		assertTrue("DESede".equals(key.getAlgorithm()));
	}

	/**
	 * M�todo que testa a grava��o do arquivo em disco
	 *  
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public void testWriteKeyToFile() throws NoSuchAlgorithmException,
			InvalidKeySpecException, IOException {
		
		File filehandler = new File("filename.key");
		SecretKey key = localcript.generateKey();
		localcript.writeKey(key, filehandler);
		assertTrue(filehandler.exists());
	}

	/**
	 * Metodo que testa a leitura de uma determinada chave em um aquivo em disco
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public void testReadKeyFromFile() throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		
		File filehandler = new File("filename.key");
		SecretKey key = localcript.readKey(filehandler);
		assertTrue("DESede".equals(key.getAlgorithm()));
	}

	/**
	 * Metodo que testa os passos de critpgrafia, encriptando e decriptando um texto simples
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public void testEncriptDecript() throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException, IOException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		String encryptedtext;
		String decriptedtext;
		SecretKey key;


		key = localcript.generateKey();
		encryptedtext = localcript.encrypt(key, texttocript);
		decriptedtext = localcript.decrypt(key, encryptedtext);
		//System.out.println(encryptedtext);
		//System.out.println(teste);
		assertEquals(true, decriptedtext.equals(texttocript));
	}
	
	/**
	 * Metodo que testa a convers�oo da chave para ser convertida em string e um array de bytes
	 *  
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public void testKeyConvert() throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKey key;
		String tmpkey;
		
		
		key = localcript.generateKey();
		tmpkey = localcript.keytostring(key);
		byte[] afterkey = localcript.stringtokey(tmpkey);
		byte[] beforekey = localcript.keytobytearray(key);
		
		assertFalse(afterkey.equals(beforekey));
	}
	
}
