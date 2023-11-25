<?php

use PHPUnit\Framework\TestCase;
use Tavsec\KubesealPhp\Kubeseal;

final class KubesealTest extends TestCase
{
    public function testSetExecutablePath(){
        $kubeseal = new Kubeseal();
        $kubeseal->setKubesealPath("/tmp/kubeseal");
        $this->assertEquals("/tmp/kubeseal", $kubeseal->getKubesealPath());
    }

    public function testSetCertificatePath(){
        $kubeseal = new Kubeseal();
        $kubeseal->setCertificatePath("/tmp/cert.pem");
        $this->assertEquals("/tmp/cert.pem", $kubeseal->getCertificatePath());
    }

    public function testStrictScopeSecretNameValidation(){
        $kubeseal = new Kubeseal();
        $this->expectException(\Tavsec\KubesealPhp\KubesealException::class);
        $kubeseal->encryptRaw("test", Kubeseal::SCOPE_STRICT);
    }

    public function testStrictScopeNamespaceValidation(){
        $kubeseal = new Kubeseal();
        $this->expectException(\Tavsec\KubesealPhp\KubesealException::class);
        $kubeseal->encryptRaw("test", Kubeseal::SCOPE_STRICT, "secretName");
    }

    public function testNamespaceScopeNamespaceValidation(){
        $kubeseal = new Kubeseal();
        $this->expectException(\Tavsec\KubesealPhp\KubesealException::class);
        $kubeseal->encryptRaw("test", Kubeseal::SCOPE_NAMESPACE);
    }

    public function testCommandNotSuccessful(){
        $kubeseal = new Kubeseal();
        $kubeseal->setKubesealPath("/bin/false");
        $this->expectException(\Exception::class);
        $kubeseal->encryptRaw("test");
    }

    public function testEncryptRawClusterWide(){
        $kubeseal = new Kubeseal();
        $kubeseal->setKubesealPath("kubeseal");
        $kubeseal->setCertificatePath("cert.pem");

        $res = $kubeseal->encryptRaw("test", Kubeseal::SCOPE_CLUSTER);
        $this->assertIsString($res);
        $this->assertStringStartsWith("Ag", $res);
    }

    public function testEncryptRawNamespaceWide(){
        $kubeseal = new Kubeseal();
        $kubeseal->setKubesealPath("kubeseal");
        $kubeseal->setCertificatePath("cert.pem");

        $res = $kubeseal->encryptRaw("test", Kubeseal::SCOPE_NAMESPACE, null, "test");
        $this->assertIsString($res);
        $this->assertStringStartsWith("Ag", $res);
    }

    public function testEncryptRawStrict(){
        $kubeseal = new Kubeseal();
        $kubeseal->setKubesealPath("kubeseal");
        $kubeseal->setCertificatePath("cert.pem");

        $res = $kubeseal->encryptRaw(data: "test", scope: Kubeseal::SCOPE_STRICT, secretName: "test", namespace: "test");
        $this->assertIsString($res);
        $this->assertStringStartsWith("Ag", $res);
    }
}
