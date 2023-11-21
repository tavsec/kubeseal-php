<?php

use PHPUnit\Framework\TestCase;

final class KubesealTest extends TestCase
{
    public function testSetExecutablePath(){
        $kubeseal = new \Tavsec\KubesealPhp\Kubeseal();
        $kubeseal->setKubesealPath("/tmp/kubeseal");
        $this->assertEquals("/tmp/kubeseal", $kubeseal->getKubesealPath());
    }

    public function testSetCertificatePath(){
        $kubeseal = new \Tavsec\KubesealPhp\Kubeseal();
        $kubeseal->setCertificatePath("/tmp/cert.pem");
        $this->assertEquals("/tmp/cert.pem", $kubeseal->getCertificatePath());
    }

    public function testStrictScopeSecretNameValidation(){
        $kubeseal = new \Tavsec\KubesealPhp\Kubeseal();
        $this->expectException(\Tavsec\KubesealPhp\KubesealException::class);
        $kubeseal->encryptRaw("test", \Tavsec\KubesealPhp\Kubeseal::SCOPE_STRICT);
    }

    public function testStrictScopeNamespaceValidation(){
        $kubeseal = new \Tavsec\KubesealPhp\Kubeseal();
        $this->expectException(\Tavsec\KubesealPhp\KubesealException::class);
        $kubeseal->encryptRaw("test", \Tavsec\KubesealPhp\Kubeseal::SCOPE_STRICT, "secretName");
    }

    public function testNamespaceScopeNamespaceValidation(){
        $kubeseal = new \Tavsec\KubesealPhp\Kubeseal();
        $this->expectException(\Tavsec\KubesealPhp\KubesealException::class);
        $kubeseal->encryptRaw("test", \Tavsec\KubesealPhp\Kubeseal::SCOPE_NAMESPACE);
    }

    public function testCommandNotSuccessful(){
        $kubeseal = new \Tavsec\KubesealPhp\Kubeseal();
        $kubeseal->setKubesealPath("/bin/false");
        $this->expectException(\Exception::class);
        $kubeseal->encryptRaw("test");
    }

    public function testEncryptRawClusterWide(){
        $kubeseal = new \Tavsec\KubesealPhp\Kubeseal();
        $kubeseal->setKubesealPath("/bin/echo");
        $this->assertEquals("test", $kubeseal->encryptRaw("test"));
    }
}
