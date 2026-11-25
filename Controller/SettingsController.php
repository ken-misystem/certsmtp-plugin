<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Controller;

use Eccube\Controller\AbstractController;
use Eccube\Entity\AuthorityRole;
use Eccube\Entity\Member;
use Eccube\Security\Voter\AuthorityVoter;
use Plugin\CertSmtp\Resource\Runtime\Config;
use Plugin\CertSmtp\Resource\Runtime\Store;
use Plugin\CertSmtp\Resource\Runtime\SafeFailure;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

final class SettingsController extends AbstractController
{
    public function __construct(private readonly Config $config, private readonly Store $store)
    {
    }

    /**
     * @Route("/%eccube_admin_route%/cert_smtp", name="cert_smtp_settings", methods={"GET"})
     * @Route("/%eccube_admin_route%/plugin/CertSmtp/config", name="cert_smtp_admin_config", methods={"GET"})
     */
    public function index(): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');
        $error = null; $history = $counts = $attempts = [];
        try {
            $history = $this->store->history();
            foreach ($this->store->counts() as $row) { $counts[$row['state']] = (int)$row['records']; }
            $attempts = $this->store->attemptHistory();
        }
        catch (\Throwable $e) { $error = $e instanceof SafeFailure ? $e->reason : 'history_unavailable'; }
        $accounts = [];
        try { $accounts = $this->config->accountStatusForUi(); }
        catch (\Throwable $e) { $error ??= $e instanceof SafeFailure ? $e->reason : 'accounts_unavailable'; }
        $response = $this->render('@CertSmtp/admin.twig',['config'=>$this->config->publicStatus(),'history'=>$history,'counts'=>$counts,'attempts'=>$attempts,'error'=>$error,'retry_allowed'=>$this->retryPermissions($history),
            'accounts'=>$accounts,'account_register_allowed'=>$this->accountAllowed('cert_smtp_account_register'),
            'account_select_allowed'=>$this->accountAllowed('cert_smtp_account_select'),'account_status_allowed'=>$this->accountAllowed('cert_smtp_account_status'),
            'account_edit_allowed'=>$this->accountAllowed('cert_smtp_account_edit')&&$this->accountAllowed('cert_smtp_account_update')]);
        $response->headers->set('Cache-Control','no-store, private');$response->headers->set('Referrer-Policy','same-origin');
        return $response;
    }

    /** @Route("/%eccube_admin_route%/cert_smtp/style.css", name="cert_smtp_styles", methods={"GET"}) */
    public function styles(): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');
        return new Response(file_get_contents(dirname(__DIR__).'/Resource/template/settings.css'),200,
            ['Content-Type'=>'text/css; charset=UTF-8','Cache-Control'=>'no-store, private','X-Content-Type-Options'=>'nosniff']);
    }

    private function accountAllowed(string $route): bool
    {
        // New credential operations must not become available merely because
        // old staff deny rules predate these routes. Require the native staff
        // privilege-administration URL permission as well as this action URL.
        $token = $this->container->get('security.token_storage')->getToken();
        if ($token === null || !$token->getUser() instanceof Member) { return false; }
        $requests = new RequestStack();
        $voter = new AuthorityVoter($this->entityManager->getRepository(AuthorityRole::class), $requests, $this->eccubeConfig);
        foreach ([$route, 'admin_setting_system_authority'] as $name) {
            $path = $this->generateUrl($name);
            $baseUrl = $this->router->getContext()->getBaseUrl();
            if ($baseUrl !== '' && str_starts_with($path, $baseUrl.'/')) { $path = substr($path, strlen($baseUrl)); }
            $requests->push(Request::create($path, 'POST'));
            try {
                if ($voter->vote($token, null, ['ROLE_ADMIN']) !== VoterInterface::ACCESS_GRANTED) { return false; }
            } finally { $requests->pop(); }
        }
        return true;
    }

    /** @Route("/%eccube_admin_route%/cert_smtp/accounts/register", name="cert_smtp_account_register", methods={"POST"}) */
    public function registerAccount(Request $request): Response
    {
        return $this->accountAction($request, true);
    }

    /** @Route("/%eccube_admin_route%/cert_smtp/accounts/select", name="cert_smtp_account_select", methods={"POST"}) */
    public function selectAccount(Request $request): Response
    {
        return $this->accountAction($request, false);
    }

    /** @Route("/%eccube_admin_route%/cert_smtp/accounts/status", name="cert_smtp_account_status", methods={"POST"}) */
    public function accountStatus(Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');
        if(!$request->isSecure()||$request->headers->get('Origin')!==$request->getSchemeAndHttpHost()||!$this->accountAllowed('cert_smtp_account_status')||!$this->isCsrfTokenValid('cert_smtp_accounts',$request->request->get('_token')))throw $this->createAccessDeniedException();
        try{$id=$request->request->get('account_id','');$enabled=$request->request->get('enabled');SafeFailure::require(is_string($id)&&in_array($enabled,['0','1'],true),'account_input');$this->config->setEnabled($id,$enabled==='1');$this->addFlash('cert_smtp_result','設定の有効・無効を変更しました。使用中の送信元は変更していません。');}
        catch(\Throwable $e){$this->addFlash('cert_smtp_result',$this->friendlyError($e instanceof SafeFailure?$e->reason:'account_operation_failed'));}
        $response=$this->redirectToRoute('cert_smtp_settings');$response->headers->set('Cache-Control','no-store, private');$response->headers->set('Referrer-Policy','same-origin');return $response;
    }

    /** @Route("/%eccube_admin_route%/cert_smtp/accounts/edit", name="cert_smtp_account_edit", methods={"GET"}) */
    public function editAccount(Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');
        if(!$this->accountAllowed('cert_smtp_account_edit')||!$this->accountAllowed('cert_smtp_account_update'))throw $this->createAccessDeniedException();
        try{
            $id=$request->query->get('id','');SafeFailure::require(is_string($id),'account_id');$edit=$this->config->editData($id);
        }catch(\Throwable){throw $this->createNotFoundException('編集できる送信設定が見つかりません。');}
        $response=$this->render('@CertSmtp/edit.twig',['edit'=>$edit]);
        $response->headers->set('Cache-Control','no-store, private');$response->headers->set('Referrer-Policy','same-origin');return $response;
    }

    /** @Route("/%eccube_admin_route%/cert_smtp/accounts/update", name="cert_smtp_account_update", methods={"POST"}) */
    public function updateAccount(Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');
        if(!$request->isSecure()||$request->headers->get('Origin')!==$request->getSchemeAndHttpHost()||!$this->accountAllowed('cert_smtp_account_edit')||!$this->accountAllowed('cert_smtp_account_update')||!$this->isCsrfTokenValid('cert_smtp_accounts',$request->request->get('_token')))throw $this->createAccessDeniedException();
        try{
            $id=$request->request->get('account_id','');SafeFailure::require(is_string($id),'account_id');$edit=$this->config->editData($id);
            $this->config->updateForm($id,$request->request->all(),$this->uploadedFiles($request));
            $message='設定を保存しました。未入力のパスワードと、選び直さなかった証明書・秘密鍵は現在のものを維持しています。';
            if($edit['active'])$message.='使用中の設定を変更したため、管理担当者へメール送信の再開確認を依頼してください。';
            $this->addFlash('cert_smtp_result',$message);
        }catch(\Throwable $e){$this->addFlash('cert_smtp_result',$this->friendlyError($e instanceof SafeFailure?$e->reason:'account_operation_failed'));}
        $response=$this->redirectToRoute('cert_smtp_settings');$response->headers->set('Cache-Control','no-store, private');$response->headers->set('Referrer-Policy','same-origin');return $response;
    }

    private function uploadedFiles(Request $request): array
    {
        $files=[];
        foreach(['p12','certificate','private_key'] as $name){
            $file=$request->files->get($name);$files[$name]='';if($file===null)continue;
            SafeFailure::require($file instanceof UploadedFile&&$file->isValid()&&$file->getSize()>0&&$file->getSize()<=262144,'upload_size');
            $raw=@file_get_contents($file->getPathname(),false,null,0,262145);SafeFailure::require(is_string($raw)&&strlen($raw)<=262144,'upload_size');$files[$name]=$raw;
        }
        return $files;
    }

    private function accountAction(Request $request, bool $register): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');
        if (!$request->isSecure() || $request->headers->get('Origin') !== $request->getSchemeAndHttpHost() || !$this->accountAllowed($register ? 'cert_smtp_account_register' : 'cert_smtp_account_select')
            || !$this->isCsrfTokenValid('cert_smtp_accounts', $request->request->get('_token'))) {
            throw $this->createAccessDeniedException();
        }
        try {
            $id = $request->request->get('account_id', '');
            SafeFailure::require(is_string($id), 'account_id');
            if ($register) {
                if($request->request->has('sender_email')){
                    $files=$this->uploadedFiles($request);
                    $this->config->registerForm($request->request->all(),$files);$files=[];
                }else{
                $path = $request->request->get('settings_file', '');
                SafeFailure::require(is_string($path) && strlen($path) <= 4096, 'account_file_path');
                $this->config->register($id, $path);
                }
            } else { $this->config->select($id); }
            $this->addFlash('cert_smtp_result', $register
                ? 'アカウントを登録しました。送信アカウントはまだ変更していません。'
                : '新しいメールの送信アカウントを変更しました。既存キューの本人・宛先・履歴は変更していません。');
        } catch (\Throwable $e) {
            $this->addFlash('cert_smtp_result', $this->friendlyError($e instanceof SafeFailure?$e->reason:'account_operation_failed'));
        }
        $response = $this->redirectToRoute('cert_smtp_settings');
        $response->headers->set('Cache-Control', 'no-store, private');$response->headers->set('Referrer-Policy','same-origin');
        return $response;
    }

    private function friendlyError(string $code): string
    {
        return match($code){
            'smtp_hostname','smtp_endpoint'=>'メールサーバー名・ポート番号を確認してください。証明書方式は対応サーバー専用です。',
            'smtp_port'=>'ポート番号は1～65535の数字で入力してください。',
            'smtp_username','smtp_sender','upload_sender'=>'メールアドレスとユーザー名を確認してください。証明書方式では同じメールアドレスを使います。',
            'smtp_credentials','secret_shape'=>'ユーザー名とパスワードを確認してください。',
            'upload_size'=>'証明書ファイルを確認してください。1ファイル256KBまでです。',
            'upload_p12'=>'P12ファイルまたは証明書のパスワードが正しくありません。',
            'upload_pair_required'=>'P12ファイル、または証明書と秘密鍵の両方を選んでください。',
            'upload_choose_one'=>'P12と、証明書・秘密鍵は同時に選ばず、どちらか一方を使ってください。',
            'upload_pair','upload_key_export'=>'証明書と秘密鍵の組み合わせ、または鍵のパスワードを確認してください。',
            'upload_identity'=>'証明書のメールアドレスが入力したメールアドレスと一致していません。',
            'upload_expired'=>'証明書の有効期限が切れているか、まだ使用できません。',
            'upload_certificate','upload_client_usage','upload_key_strength'=>'この証明書は使用できません。発行担当者へ確認してください。',
            'upload_standard'=>'証明書を使う場合は、詳細設定で「クライアント証明書を使う」を選んでください。',
            'account_username_duplicate'=>'同じ送信設定がすでに登録されています。一覧を確認してください。',
            'account_delivery_busy'=>'メールを送信中のため保存できません。少し待ってからもう一度保存してください。',
            'account_edit_conflict'=>'別の画面で設定が変更されました。編集画面を開き直して確認してください。',
            'account_not_editable'=>'この設定は以前のメールを守るために保存されています。現在の設定を編集してください。',
            'upload_password_without_file'=>'証明書のパスワードを変える場合は、証明書・鍵のファイルも選び直してください。',
            'account_limit'=>'登録できる送信設定は20件までです。',
            'account_storage_limit'=>'証明書などの合計容量が大きすぎます。管理担当者へご連絡ください。',
            'account_disabled'=>'無効な設定は使用できません。',
            'account_active_disable'=>'使用中の設定は無効にできません。先に別の送信設定へ切り替えてください。',
            'account_label'=>'設定名は64文字以内で入力してください。',
            default=>'設定を保存できませんでした。入力内容を確認してください。解決しない場合は管理担当者へご連絡ください。',
        };
    }

    private function retryPermissions(array $history): array
    {
        $allowed = [];
        $token = $this->container->get('security.token_storage')->getToken();
        if ($token === null || !$token->getUser() instanceof Member) {
            return $allowed;
        }
        // Member roles do not distinguish read-only staff. Evaluate each POST
        // URL with EC-CUBE's native authority voter and an isolated main request.
        // Never replace the live request or reimplement its deny-URL matching.
        $requests = new RequestStack();
        $voter = new AuthorityVoter($this->entityManager->getRepository(AuthorityRole::class), $requests, $this->eccubeConfig);
        foreach ($history as $row) {
            if ($row['state'] !== 'failed' || !$row['safe_retry']) {
                continue;
            }
            $path = $this->generateUrl('cert_smtp_retry', ['id'=>$row['id']]);
            $baseUrl = $this->router->getContext()->getBaseUrl();
            if ($baseUrl !== '' && str_starts_with($path, $baseUrl.'/')) {
                $path = substr($path, strlen($baseUrl));
            }
            $requests->push(Request::create($path, 'POST'));
            try {
                $allowed[$row['id']] = $voter->vote($token, null, ['ROLE_ADMIN']) === VoterInterface::ACCESS_GRANTED;
            } finally {
                $requests->pop();
            }
        }
        return $allowed;
    }

    /** @Route("/%eccube_admin_route%/cert_smtp/retry/{id}", name="cert_smtp_retry", methods={"POST"}, requirements={"id"="[0-9a-f]{32}"}) */
    public function retry(Request $request, string $id): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');
        if (!$this->isCsrfTokenValid('cert_smtp_retry_'.$id,$request->request->get('_token'))) {
            throw $this->createAccessDeniedException();
        }
        try {
            $ok = $this->store->manualRetry($id);
            $this->addFlash('cert_smtp_result',$ok ? '再送待ちに変更しました。送信完了ではありません。' : '再送できる状態ではありません。結果不明のメールは自動再送しません。');
        } catch (\Throwable) { $this->addFlash('cert_smtp_result','再送予約を確認できません。操作を繰り返さず履歴を確認してください。'); }
        return $this->redirectToRoute('cert_smtp_settings');
    }
}
