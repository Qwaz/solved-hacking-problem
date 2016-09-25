<section id="intro" class="intro-section">
        <div class="container">
            <div class="row">
                <div class="col-lg-12">
		  <center>
                    <h1>Login</h1>
		  <form name="f" method="post" action="?page=login">
                    <p><input class="form-control" style="color:#000;width:300px;" placeholder="ID" type="text" name="id" />
		  <input class="form-control" style="color:#000;width:300px;" placeholder="PW" type="text" name="pw" /></p>
                    <a class="btn btn-default page-scroll" onclick="f.submit();">Login</a>
		  </form>
		  <?php
		  if($_POST){
			if($_SESSION[id]){
			  echo "<script>alert('You have already logged in.');history.go(-1);</script>";
			  exit();
			}

			$sql = "select * from member where id = '".trim($_POST[id])."'";
			$result = @mysql_query($sql);
			$data = @mysql_fetch_array($result);
			if($data[id]){
			  if($_POST[pw] == $data[pw]){
				$_SESSION[id] = $data[id];
				echo "<script>alert('Hello $_SESSION[id]');location.href='./';</script>";
			  }else{
				echo "<script>history.go(-1);</script>";
				exit();
			  }
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
