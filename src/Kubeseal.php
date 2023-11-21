<?php

namespace Tavsec\KubesealPhp;

use Symfony\Component\Process\Process;

class Kubeseal
{
    const SCOPE_CLUSTER = "cluster-wide";
    const SCOPE_NAMESPACE = "namespace-wide";
    const SCOPE_STRICT = "strict";
    private string $kubesealPath = "/usr/local/bin/kubeseal";
    private ?string $certificatePath = null;

    public function setKubesealPath(string $kubesealPath): Kubeseal
    {
        $this->kubesealPath = $kubesealPath;
        return $this;
    }

    public function setCertificatePath(?string $certificatePath): Kubeseal
    {
        $this->certificatePath = $certificatePath;
        return $this;
    }

    /**
     * @throws \Exception
     */
    public function encryptRaw(string $data, string $scope = self::SCOPE_CLUSTER, ?string $secretName = null, ?string $namespace = null): string
    {
        if($scope === self::SCOPE_STRICT){
            if(!$secretName) throw new KubesealException("Secret name is required for strict scope");
            if(!$namespace) throw new KubesealException("Namespace is required for strict scope");
        }

        if($scope === self::SCOPE_NAMESPACE){
            if(!$namespace) throw new KubesealException("Namespace is required for namespace-wide scope");
        }

        $cert = $this->certificatePath ? (" --cert " . $this->certificatePath) : "";
        $namespaceFlag = $namespace ? "--namespace $namespace" : "";
        $nameFlag = $secretName ? "--name $secretName" : "";

        $kubesealProcess = new Process([
            "/bin/sh", "-c",
            "echo -n '" . $data . "' | " . $this->kubesealPath .
            $cert .
            " --raw $namespaceFlag $nameFlag --scope $scope"
        ]);
        $kubesealProcess->run();
        $kubesealProcess->wait();
        if(!$kubesealProcess->isSuccessful()){
            throw new \Exception($kubesealProcess->getErrorOutput());
        }
        return $kubesealProcess->getOutput();
    }

    public function getKubesealPath(): string
    {
        return $this->kubesealPath;
    }

    public function getCertificatePath(): ?string
    {
        return $this->certificatePath;
    }
}
