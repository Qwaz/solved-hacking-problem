<?php
  if(!$_SESSION[id]){
	echo "<script>location.href('?page=login');</script>";
	exit();
  }
?>
  <section id="intro" class="intro-section">
        <div class="container">
            <div class="row">
                <div class="col-lg-12">
		  <center>
                    <h1>Rank</h1>
		  <table style="border:1px solid white" width=80%>
			<tr style="border:1px solid white">
			  <th style="border:1px solid black;text-align:center;background-color:#FFF"><font color=#000>RANK</font></th>
			  <th style="border:1px solid black;text-align:center;background-color:#FFF"><font color=#000>ID</font></th>
			  <th style="border:1px solid black;text-align:center;background-color:#FFF"><font color=#000>Point</font></th>
			  <th style="border:1px solid black;text-align:center;background-color:#FFF"><font color=#000>LastAuth</font></th>
			</tr>
			<?php
			$sql = "select * from member order by point desc, lastauth asc limit 0,100";
			$result = @mysql_query($sql);

			for($i=1; $list=mysql_fetch_array($result); $i++){
			  if($list[id] == "admin" || $list[point] == 0)
				continue;
		  ?>
		  <tr align="center">
		  <td style="border:1px solid;" align="center"><font color=#000><?php echo $i; ?></font></td>
		  <td style="border:1px solid;">
		  <font color=#000><?php echo $list[id]; ?></font></td>
		  <td style="border:1px solid;"><font color=#000><?php echo $list[point]; ?></font></td>
		  <td style="border:1px solid;"><font color=#000><?php echo date("Y-m-d H\h i\m s\s",$list[lastauth]); ?></font></td>
		  </tr>
		  <?php
			}
			mysql_free_result($result);
		  ?>
		  </table>
		  </center>
                </div>
            </div>
        </div>
    </section>
