 <section id="intro" class="intro-section">
        <div class="container">
            <div class="row">
                <div class="col-lg-12">
		  <center>
                    <h1>Join</h1>
		  <form name="f" method="post" action="?page=register">
                    <p><input class="form-control" style="color:#000;width:300px;" placeholder="ID" type="text" name="id" />
		  <input class="form-control" style="color:#000;width:300px;" placeholder="PW" type="text" name="pw" /></p>
                    <a class="btn btn-default page-scroll" onclick="f.submit();">Join</a>
		  </form>
		  <?php
		  if($_POST){
			if($_SESSION[id]){
			  echo "<script>alert('You have already logged in.');history.go(-1);</script>";
			  exit();
			}
			if($_POST[id] == ""){
			  echo "<script>alert('Input your ID.');history.go(-1);</script>";
			  exit();
			}
			if($_POST[pw] == ""){
			  echo "<script>alert('Input your password.');history.go(-1);</script>";
			  exit();
			}
			if(strlen(trim($_POST[id])) > 20){
			  echo "<script>alert('Can't create ID bigger than 20 bytes.');history.go(-1);</script>";
			  exit();
			}
			if(strlen($_POST[pw]) > 32){
			  echo "<script>alert('Can't create password bigger than 32 bytes.');history.go(-1);</script>";
			  exit();
			}
			if(!preg_match("/[[:alnum:]+]{4,20}/",$_POST[id])) {
			  echo "<script>alert('Invalid ID.');history.go(-1);</script>";
			  exit();
			}

			if($_POST[id] && $_POST[pw])
			{
			  $_POST[id]=htmlspecialchars(addslashes($_POST[id]));
			  $_POST[pw]=htmlspecialchars(addslashes($_POST[pw]));

			  $sql = "select idx from member where id = '".trim($_POST[id])."'";
			  $result = @mysql_query($sql);
			  $data = @mysql_fetch_array($result);

			  if($data[idx]){
				echo "<script>alert('ID already exists.');history.go(-1);</script>";
				exit();
			  }

			  $time=time();
			  $sql = @mysql_query("insert into member (id, pw, point, lastauth) values ('".trim($_POST[id])."', '".trim($_POST[pw])."', 0, $time)");
			  $_SESSION[id]=$_POST[id];
			  echo "<script>alert('Register completed.');location.href='./';</script>";
			}else{
			  echo "<script>history.go(-1);</script>";
			  exit();
			}
		  }
		  ?>
		  </center>
                </div>
            </div>
        </div>
    </section>
