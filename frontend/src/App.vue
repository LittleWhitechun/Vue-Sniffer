<template>
  <Sniffer msg="Welcome to Your Vue.js App"/>
  <!-- <Taishi/> -->
  <el-footer>Ucas | LittleWhitechun | WhiteShark @2021 </el-footer>
</template>

<script>
import Sniffer from './components/Sniffer.vue'
// import Taishi from './components/Taishi.vue';
export default {
  name: 'App',
  components: {
    Sniffer,
    // Taishi
  }
}
</script>

<style>
body{
  background-color: rgb(241, 241, 247);
  padding: 0;
  margin: 0;
  vertical-align:bottom;
}
.el-footer{
  position: fixed;
  bottom: 0;
  left: 45%;
  font-family: "Gill Sans", "Gill Sans MT", Calibri, "Trebuchet MS", sans-serif;
  font-size: 0.75em;
}
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 0;
  opacity: 0.835;
  
  /* background-image: url("../img/bkg.png"); */
}
</style>
