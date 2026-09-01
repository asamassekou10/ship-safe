<?php require_once 'config.php'; ?>
<div class="lang-picker">Here's the picker.</div>
<script>
    var lang = document.location.href.substring(document.location.href.indexOf("default=") + 8);
    document.write("<option>" + lang + "</option>");
</script>
