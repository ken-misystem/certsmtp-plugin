<?php
namespace Plugin\CertSmtp;
final class Nav implements \Eccube\Common\EccubeNav
{
    public static function getNav():array
    {
        return ['cert_smtp'=>['name'=>'メール送信設定','icon'=>'fa-envelope','url'=>'cert_smtp_settings']];
    }
}
