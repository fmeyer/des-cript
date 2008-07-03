package org.fmeyer.crypto;

/*
 * Copyright (c) 2006 Fernando Meyer
 * Author Fernando Meyer <fernando@fmeyer.org>
 * Java doc de referencia: http://java.sun.com/j2se/1.4.2/docs/api/javax/crypto/package-summary.html
 * Documentacao de referencia: http://en.wikipedia.org/wiki/Triple_DES
 */

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

public class TripleDES {

	/**
	 * Gera a chave baseada no algoritmo DES
	 * 
	 * @return {@link SecretKey}
	 * @throws NoSuchAlgorithmException
	 */
	public SecretKey generateKey() throws NoSuchAlgorithmException {
		KeyGenerator keygen = KeyGenerator.getInstance("DESede");
		return keygen.generateKey();
	}

	/**
	 * Grava a chave secreta em um arquivo para poder transportar para qualquer
	 * lugar. como em um pendrive por exemplo
	 * 
	 * @param DESkey chave a ser persistida em disco 
	 * @param filehandler handler para arquivo em disco
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */

	public void writeKey(SecretKey DESkey, File filehandler)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {

		/*
		 * Converte a chave em um array de bytes para ser gravada em disco.
		 */

		byte[] rawkey = keytobytearray(DESkey);

		/*
		 * Grava a chave propriamente dita no handler de arquivo passado
		 */
		FileOutputStream out = new FileOutputStream(filehandler);
		out.write(rawkey);
		out.close();
	}

	/**
	 * 
	 * @param DESkey chave a ser convertida para string
	 * @return byte[]
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public String keytostring(SecretKey DESkey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		String tmpKey = new String();
		byte[] rawkey = keytobytearray(DESkey);

		for (byte b : rawkey) {
			tmpKey += Integer.toHexString(b);
		}

		return tmpKey;
	}

	/**
	 * 
	 * @param strKey chave no formato string para ser convertida para um array de bytes
	 * @return byte[]
	 */
	public byte[] stringtokey(String strKey) {
		BigInteger big = new BigInteger(strKey, 16);
		byte[] valor = big.toByteArray();
		return valor;
	}

	/**
	 * 
	 * @param DESkey chave no formato {@link SecretKey} para ser convertida para um array de bytes
	 * @return byte[]
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public byte[] keytobytearray(SecretKey DESkey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
		DESedeKeySpec keyspec = (DESedeKeySpec) keyfactory.getKeySpec(DESkey,
				DESedeKeySpec.class);

		byte[] rawkey = keyspec.getKey();

		return rawkey;
	}

	/**
	 * L� a chave Tipla de um arquivo especifico.
	 * 
	 * @param filehandler filehandler do arquivo em disco que contem uma chave serializada
	 * @return {@link SecretKey}
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 */

	public SecretKey readKey(File filehandler) throws IOException,
			NoSuchAlgorithmException, InvalidKeyException,
			InvalidKeySpecException {

		/*
		 * Le os bytes de um arquivo para um array na memoria para ser
		 * convertido a uma chave
		 */

		DataInputStream in = new DataInputStream(new FileInputStream(filehandler));
		byte[] rawkey = new byte[(int) filehandler.length()];
		in.readFully(rawkey);
		in.close();

		// Converte o array de bytes para uma chave SecretKey

		DESedeKeySpec keyspec = new DESedeKeySpec(rawkey);
		SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
		SecretKey key = keyfactory.generateSecret(keyspec);
		return key;
	}

	/**
	 * Usa uma chave especifica para criptografar um inputstream para um
	 * outputstream este metodo usa a classe CipherOutputStream para
	 * criptografar e gravar os arquivos ao mesmo tempo.
	 * @param key Chave a ser usada na criptogravia 
	 * @param in texto a ser criptografado.
	 * @return {@link String}
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws IOException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String encrypt(SecretKey key, String in)
			throws NoSuchAlgorithmException, InvalidKeyException,
			NoSuchPaddingException, IOException, IllegalBlockSizeException,
			BadPaddingException {

		// Pega a instancia do engine de criptografia
		Cipher cipher = Cipher.getInstance("DESede");
		cipher.init(Cipher.ENCRYPT_MODE, key);

		// Pega os bytes do string
		byte[] buffer = new byte[in.length()];
		buffer = in.getBytes();

		buffer = cipher.doFinal(buffer);

		// monta o retorno para o string
		String ret = new String(buffer);

		// por seguranca nao deixar dados no array
		// ao sair da funcao o objeto ret vai ser coletado pelo garbage colector
		java.util.Arrays.fill(buffer, (byte) 0);

		return ret;
	}

	/**
	 * Usa uma chave especifica para descriptografar um inputstream para um
	 * outputstream
	 * 
	 * @param key Chave usada na operacao
	 * @param in Texto criptografado a ser decriptografado
	 * @return {@link SecretKey}
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws IOException
	 * @throws IllegalBlockSizeException
	 * @throws NoSuchPaddingException
	 * @throws BadPaddingException
	 */
	public String decrypt(SecretKey key, String in)
			throws NoSuchAlgorithmException, InvalidKeyException,
			IllegalBlockSizeException, NoSuchPaddingException,
			BadPaddingException {

		// Pega a instancia do engine de criptografia
		Cipher cipher = Cipher.getInstance("DESede");
		cipher.init(Cipher.DECRYPT_MODE, key);

		// Pega os bytes do string
		byte[] buffer = new byte[in.length()];
		buffer = in.getBytes();

		// monta o retorno para o string
		buffer = cipher.doFinal(buffer);

		return new String(buffer);
	}
}
