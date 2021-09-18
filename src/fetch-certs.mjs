#!/usr/bin/env zx

const tls = require('tls')
const net = require('net')
const crypto = require('crypto')

function parseCertificate(rawData) {
  let ctx = tls.createSecureContext({
    cert: '-----BEGIN CERTIFICATE-----\n' + rawData + '\n-----END CERTIFICATE-----'
  })
  let socket = new tls.TLSSocket(new net.Socket(), { secureContext: ctx })
  try {
    return socket.getCertificate()
  } finally {
    socket.destroy()
  }
}

function formatAttributes(attributes) {
  return Object.entries(attributes).map(([key, value]) => `${key} = ${value}`).join(', ')
}

function formatPubKey(rawData) {
  return crypto.createPublicKey(
    '-----BEGIN CERTIFICATE-----\n' + rawData + '\n-----END CERTIFICATE-----'
  )
    .export({ format: 'pem', type: 'spki' })
}

const resp = await fetch('https://de.dscg.ubirch.com/trustList/DSC/')
const text = await resp.text()
const { certificates } = JSON.parse(text.substring(text.indexOf('\n') + 1))

const convertedCerts = certificates.map(({ rawData }) => {
  const cert = parseCertificate(rawData)
  return {
    issuer: formatAttributes(cert.issuer),
    subject: formatAttributes(cert.subject),
    notbefore: new Date(cert.valid_from).getTime(),
    notafter: new Date(cert.valid_to).getTime(),
    pubkey: formatPubKey(rawData),
    rawX509data: rawData
  }
})

console.log(JSON.stringify({ certs: convertedCerts }, null, 2))
