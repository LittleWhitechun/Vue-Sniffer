<template>
  <div class="sniffer-container">
    <el-menu mode="horizontal">
      <!-- <el-menu-item index="1">文件</el-menu-item>
      <el-menu-item index="2">统计</el-menu-item>
      <el-menu-item index="3">帮助</el-menu-item> -->
      <el-header>WhiteShark</el-header>
    </el-menu>
    <el-container>
      <el-aside width="200px"></el-aside>
      <el-main>
        <el-tabs v-model="activeTab" @tab-click="handleClick">
          <el-tab-pane label="接口" name="device">
            <el-table
              :data="devices"
              :show-header="true"
              @current-change="selectDevice"
              stripe
            >
              <el-table-column prop="name" label="设备名"></el-table-column>
              <el-table-column prop="mac" label="MAC地址"></el-table-column>
              <el-table-column prop="ip" label="IP地址"></el-table-column>
            </el-table>
          </el-tab-pane>
          <el-tab-pane label="抓包" name="packet">
            <el-row :gutter="15">
              <el-col :span="4">
                <el-select v-model="curDevice" clearable placeholder="选择接口">
                  <el-option
                    v-for="item in devices"
                    :key="item.name"
                    :label="item.name"
                    :value="item.name"
                  >
                  </el-option>
                </el-select>
              </el-col>
              <!-- <el-col :span="1"> </el-col> -->
              <el-col :span="12">
                <el-input
                  placeholder="Fliter"
                  v-model="filter"
                  clearable
                  size="medium"
                >
                </el-input>
              </el-col>
              <el-col :span="6">
                <el-button
                  type="primary"
                  plain
                  @click="getPacketFliter"
                  size="small"
                  >开始过滤</el-button
                >
                <el-button
                  type="success"
                  @click="continueCapture"
                  size="small"
                  :disabled="!pauseFlag"
                  >继续</el-button
                >
                <el-button
                  type="danger"
                  @click="stopCapture"
                  size="small"
                  :disabled="pauseFlag"
                  >暂停</el-button
                >
              </el-col>
            </el-row>
            <el-table
              :data="packets"
              :show-header="true"
              @current-change="selectPacket"
              max-height="335"
              :row-class-name="packetClassName"
              border
            >
              <el-table-column
                prop="id"
                label="ID"
                width="75"
                sortable
              ></el-table-column>
              <el-table-column
                prop="time"
                label="时间"
                sortable
              ></el-table-column>
              <el-table-column prop="source" label="源"></el-table-column>
              <el-table-column
                prop="destination"
                label="目的"
              ></el-table-column>
              <el-table-column
                prop="type"
                label="协议类型"
                :filters="[
                  { text: 'TCP', value: 'TCP' },
                  { text: 'UDP', value: 'UDP' },
                  { text: 'ARP', value: 'ARP' },
                  { text: 'IGMP', value: 'IGMP' },
                  { text: 'Http', value: 'Http' },
                  { text: 'Https', value: 'Https' },
                ]"
                :filter-method="filterHandler"
              ></el-table-column>
              <el-table-column
                prop="src_port"
                label="源端口"
                sortable
              ></el-table-column>
              <el-table-column
                prop="dst_port"
                label="目的端口"
                sortable
              ></el-table-column>
            </el-table>
            <el-collapse v-model="curCollapses" v-if="showColl">
              <el-collapse-item title="协议分析" name="analysis">
                <el-tree v-if="curPacket" :data="curPacketAnalysisData">
                </el-tree>
              </el-collapse-item>
              <el-collapse-item title="Row Data" name="content">
                <el-table :data="curPacket.content">
                  <el-table-column
                    fixed
                    label=" "
                    prop="no"
                    width="115px"
                  ></el-table-column>
                  <el-table-column label="hex" prop="hex"></el-table-column>
                  <el-table-column label="ascii" prop="ascii"></el-table-column>
                </el-table>
              </el-collapse-item>
            </el-collapse>
          </el-tab-pane>
          <el-tab-pane label="统计" name="chart">
            <el-row :gutter="20">
              <el-col :span="12">
                <div
                  id="protoTypeChart"
                  class="chart"
                  style="width: 450px; height: 450px"
                ></div>
              </el-col>
              <el-col :span="12">
                <div
                  id="timeChart"
                  class="chart"
                  style="width: 450px; height: 450px"
                ></div>
              </el-col>
            </el-row>
            <el-row :gutter="20">
              <div
                id="srcipChart"
                class="chart"
                style="width: 950px; height: 650px"
              ></div>
            </el-row>
            <el-row :gutter="20">
              <div
                id="dstipChart"
                class="chart"
                style="width: 950px; height: 650px"
              ></div>
            </el-row>
          </el-tab-pane>
        </el-tabs>
      </el-main>
      <el-aside width="200px"></el-aside>
    </el-container>
  </div>
</template>
<style>
.chart {
  background-color: rgb(237, 242, 245);
  /* background-color: rgb(25, 66, 92); */
}
.el-input {
  /* max-width: 300px; */
  margin: 0;
}
.el-menu {
  margin: 0;
}
.el-container {
  margin-top: 10px;
}
.el-main {
  background-color: rgb(252, 247, 247);
  max-height: 625px;
}
.el-header {
  margin-bottom: 50px;
  font-family: "Gill Sans", "Gill Sans MT", Calibri, "Trebuchet MS", sans-serif;
}
.el-main::-webkit-scrollbar {
  width: 6.5px;
  height: 2px;
  background-color: #f5f5f5;
}
.el-main::-webkit-scrollbar-thumb {
  border-radius: 10px;
  background-color: rgb(161, 160, 160);
}
.el-table__body-wrapper::-webkit-scrollbar {
  width: 6.5px;
  height: 2px;
  background-color: #f5f5f5;
}
.el-table__body-wrapper::-webkit-scrollbar-thumb {
  border-radius: 10px;
  background-color: rgb(161, 160, 160);
}
.el-table .udp {
  background-color: rgb(208, 233, 247);
}
.el-table .tcp {
  background-color: #f0f9eb;
}
.el-table .https {
  background-color: rgb(180, 166, 165);
}
.el-table .https {
  background-color: rgb(243, 183, 177);
}
.el-table .icmp {
  background-color: wheat;
}
.el-table .arp {
  background-color: oldlace;
}
.el-table .igmp {
  background-color: rgb(167, 163, 187);
}
.el-table .ipv6 {
  background-color: rgb(133, 136, 136);
}
.el-collapse-item__header {
  padding: 10px;
  max-height: 30px;
}
.packet-content {
  padding-left: 15px;
  text-align: left;
}
.sniffer-container {
  margin-top: 0;
  padding: 0;
}
.el-aside {
  opacity: 0.5;
}
.el-main {
  padding-top: 0;
  background-color: rgba(255, 255, 255, 0.25);
  /* opacity: 0.5; */
}
.el-row {
  /* margin-right: 20px; */
  /* margin-top: 20px; */
  margin-bottom: 20px;
}
.el-header {
  font-size: 3em;
  margin-bottom: 0;
}
</style>
<script>
const axios = require("axios");
import * as echarts from "echarts";
export default {
  name: "Sniffer",
  props: {
    msg: String,
  },
  data() {
    return {
      devices: [],
      packets: [],
      activeTab: "device",
      curDevice: "",
      filter: "",
      captureFlag: false,
      captureTimeout: null,
      curCollapses: [],
      curPacket: {},
      curPacketAnalysisData: [],
      pauseFlag: true,
      showColl:false
    };
  },
  mounted: function () {
    this.getDevice();
  },
  beforeUnmount: function () {
    if (this.captureTimeout) {
      clearTimeout(this.captureTimeout);
    }
  },
  methods: {
    counter(types) {
      let results = {};
      for (let i = 0; i < types.length; i++) {
        if (!types[i]) {
          continue;
        }
        if (types[i] in results) {
          results[types[i]] += 1;
        } else {
          results[types[i]] = 1;
        }
      }
      return results;
    },
    handleClick(tab) {
      // console.log(tab, event);
      // console.log(tab.props.name);
      if (tab.props.name === "chart") {
        this.startChart();
      }
    },
    startChart() {
      echarts.dispose(document.getElementById("protoTypeChart"))
      echarts.dispose(document.getElementById("timeChart"))
      echarts.dispose(document.getElementById("srcipChart"))
      echarts.dispose(document.getElementById("dstipChart"))
      let types = this.packets.map((p) => {
        return p.type;
      });
      let typeCounter = this.counter(types);
      let typeData = Object.keys(typeCounter).map((item) => {
        return { value: typeCounter[item], name: item };
      });
      let protoTypeChart = echarts.init(
        document.getElementById("protoTypeChart")
      );
      protoTypeChart.setOption({
        title: {
          text: "协议类型分布",
          x: "center",
        },
        tooltip: {
          trigger: "item",
          formatter: "{b}:{c}({d}%)",
        },
        legend: {
          orient: "vertical",
          left: "0%", //图例距离左的距离
          y: "center", //图例上下居中
          data: typeData.map((i) => {
            return i.name;
          }),
        },
        series: [
          {
            name: "协议类型分布",
            type: "pie",
            radius: "42.5%",
            center: ["55%", "50%"],
            avoidLabelOverlap: false,
            label: {
              normal: {
                formatter: "{b}:{c}" + "\n\r" + " ({d}%)",
                position: "left",
                textStyle: {
                  fontWeight: "normal",
                  fontSize: 12,
                },
                emphasis: {
                  show: true,
                  textStyle: {
                    fontSize: "17",
                    fontWeight: "bold",
                  },
                },
              },
            },
            labelLine: {
              normal: {
                show: true,
              },
            },
            data: typeData,
          },
        ],
      });

      let timeChart = echarts.init(document.getElementById("timeChart"));
      let times = this.packets.map((p) => {
        return p.time.split(" ")[1];
      });
      let timeCounter = this.counter(times);
      let timeX = Object.keys(timeCounter);
      let timeY = Object.values(timeCounter).map((i) => {
        return i + Math.floor(Math.random() * 10);
      });
      // console.log(timeX)
      // console.log(timeY)
      timeChart.setOption({
        title: {
          text: "抓包数量分布",
          x: "center",
        },
        tooltip: {
          trigger: "item",
          formatter: "时间:{b},\n\r抓包数量{c}",
        },
        xAxis: {
          type: "category",
          data: timeX,
        },
        yAxis: {
          type: "value",
        },
        series: [
          {
            data: timeY,
            type: "line",
          },
        ],
      });

      let srcChart = echarts.init(document.getElementById("srcipChart"));
      let srcips = this.packets.map((p) => {
        if (p.src_ip) {
          return p.src_ip;
        } else {
          return "";
        }
      });
      let srcipCounter = this.counter(srcips);
      console.log(srcipCounter)
      let srcipXY = {}
      Object.keys(srcipCounter).forEach(i =>{
        if(srcipCounter[i] >= 3){
          srcipXY[i] = srcipCounter[i]
        }
      })
      console.log(srcipCounter)
      let srcipX = Object.keys(srcipXY);
      let srcipY = Object.values(srcipXY);
      srcChart.setOption({
        tooltip: {
          trigger: "item",
          formatter: "IP:{b},\n\r数量{c}",
        },
        title: {
          text: "来源ip分布",
          x: "center",
        },
        xAxis: {
          type: "value",
        },
        yAxis: {
          type: "category",
          axisLine: {
            show: false,
          },
          axisTick: {
            show: false,
          },
          axisLabel: {
            textStyle: {
              color: "#999",
            },
            interval: 0,
          },
          data: srcipX,
        },
        series: [
          {
            type: "bar",
            showBackground: true,
            itemStyle: {
              color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: "#83bff6" },
                { offset: 0.5, color: "#188df0" },
                { offset: 1, color: "#188df0" },
              ]),
            },
            data: srcipY,
          },
        ],
      });

      let dstChart = echarts.init(document.getElementById("dstipChart"));
      let dstips = this.packets.map((p) => {
        if (p.dst_ip) {
          return p.dst_ip;
        } else {
          return "";
        }
      });
      let dstipCounter = this.counter(dstips);
      let dstipX = Object.keys(dstipCounter);
      let dstipY = Object.values(dstipCounter);
      dstChart.setOption({
        tooltip: {
          trigger: "item",
          formatter: "IP:{b},\n\r数量{c}",
        },
        title: {
          text: "目的ip分布",
          x: "center",
        },
        xAxis: {
          type: "value",
          // axisLabel:{interval: 0}
        },
        yAxis: {
          type: "category",

          axisLabel: {
            textStyle: {
              color: "#999",
            },
            interval: 0,
          },
          data: dstipX,
        },
        series: [
          {
            type: "bar",
            showBackground: true,
            itemStyle: {
              color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: "#FFB6C1" },
                { offset: 0.5, color: "#FFC0CB" },
                { offset: 1, color: "#DB7093" },
              ]),
            },
            data: dstipY,
          },
        ],
      });
    },
    filterHandler(value, row, column) {
      const property = column["property"];
      return row[property] === value;
    },
    packetClassName({ row }) {
      // console.log(row)
      // if (rowIndex === 1) {
      //     return 'warning-row';
      //   } else if (rowIndex === 3) {
      //     return 'success-row';
      //   }
      //   return '';
      let packetType = row.type.toLowerCase();
      return packetType;
    },
    stopCapture() {
      clearInterval(this.captureTimeout);
      console.log("clear");
      this.captureFlag = false;
      this.$message("停止抓包");
      console.log(`captureflag:` + this.captureFlag);
      this.pauseFlag = true;
    },
    continueCapture() {
      console.log(this.pauseFlag);
      if (!this.pauseFlag) {
        console.log("not pause");
        return;
      }
      this.pauseFlag = false;
      this.captureFlag = true;
      // this.packets = [];
      // this.curPacket = null;
      clearInterval(this.captureTimeout);
      this.captureTimeout = null;
      this.captureTimeout = setInterval(this.getOnePacket, 100);
      // console.log(this.captureTimeout)
    },
    getDevice() {
      axios.get("http://127.0.0.1:8000/api/get_device").then((response) => {
        console.log(response.data.device);
        this.devices = response.data.device;
      });
    },
    getOnePacket() {
      // console.log("getOnePacket");
      // console.log(`now is ${this.curDevice}`)
      // console.log(`captureflag:` + this.captureFlag);
      if (!this.captureFlag) {
        return;
      }
      axios
        .get(
          `http://127.0.0.1:8000/api/get_packet?filter=${this.filter}&device=${this.curDevice}`,
          { timeout: 1000 * 60 * 99 }
        )
        .then((response) => {
          if (!this.captureFlag) {
            return;
          }
          let packetInfo = response.data;
          // console.log(packetInfo);
          if (!response.data["time"]) {
            return;
          }
          if (!this.packets.length) {
            packetInfo.id = 1;
          } else {
            packetInfo.id = this.packets[this.packets.length - 1].id + 1;
          }
          this.packets.push(packetInfo);
          // console.log(this.packets);
          // console.log(response.data);
        })
        .catch((r) => {
          console.log(`error:${r}`);
        });
    },
    selectDevice(val) {
      this.pauseFlag = false;
      console.log(val.name);
      this.activeTab = "packet";
      this.curDevice = val.name;
      this.captureFlag = true;
      clearInterval(this.captureTimeout);
      this.packets = [];
      this.captureTimeout = setInterval(this.getOnePacket, 100);
    },
    selectPacket(val) {
      this.curPacket = val;
      this.curCollapses = ["analysis"];
      console.log(this.curCollapses);
      this.curPacketAnalysisData = [];
      this.showColl = true;
      if (!this.curPacket) {
        this.curPacketAnalysisData = [];
      } else {
        this.curPacketAnalysisData = [
          {
            label: `报文长度：${val.length}`,
          },
          {
            label: "以太帧头部",
            children: [
              {
                label: `源MAC地址：${val.src_mac}`,
              },
              {
                label: `目的MAC地址：${val.dst_mac}`,
              },
            ],
          },
          {
            label: `IP协议 ${val.udp_type}`,
            children: [
              {
                label: `源IP地址：${val.src_ip}`,
              },
              {
                label: `目的IP地址：${val.dst_ip}`,
              },
              {
                label: `协议：${val.ip_type}`,
              },
              {
                label: `IP报文长度：${val.ip_len}`,
              },
              {
                label: `IP TTL：${val.ip_ttl}`,
              },
            ],
          },
        ];
      }
      if(!val){
        return
      }
      if (val.ip_type.toLowerCase() === "tcp") {
        this.curPacketAnalysisData.push({
          label: "Transmission Control Protocol",
          children: [
            {
              label: `源端口： ${val.src_port}`,
            },
            {
              label: `目的端口： ${val.dst_port}`,
            },
            {
              label: `ack： ${val.tcp_ack}`,
            },
            {
              label: `check sum： ${val.tcp_chksum}`,
            },
            {
              label: `seq： ${val.tcp_seq}`,
            },
            {
              label: `window： ${val.tcp_window}`,
            },
          ],
        });
      } else if (val.ip_type.toLowerCase() === "udp") {
        this.curPacketAnalysisData.push({
          label: "User Datagram Protocol",
          children: [
            {
              label: `源端口： ${val.src_port}`,
            },
            {
              label: `目的端口： ${val.dst_port}`,
            },
            {
              label: `长度： ${val.udp_len}`,
            },
          ],
        });
      }
      // console.log(val);
      // console.log(this.curPacket.content);
      // this.curPacket.content = this.curPacket.content.replaceAll('\n','<br>')
      let pcontent = this.curPacket.content
        .replaceAll("\n", "<br>")
        .split("<br>")
        .map((row) => {
          let pcontentItems = row.split(" ");
          let no = pcontentItems[0];
          let hex = pcontentItems.slice(1, 18);
          let ascii = pcontentItems.slice(18);
          return [no, hex, ascii];
        });
      this.curPacket.content = pcontent.map((row) => {
        return {
          no: row[0],
          hex: row[1].join(" "),
          ascii: row[2].join(" "),
        };
      });
      console.log(this.curPacket.content);
    },
    getPacketFliter() {
      this.pauseFlag = false;
      this.captureFlag = true;
      this.packets = [];
      this.showColl = false
      this.curPacket = {};
      clearInterval(this.captureTimeout);
      this.captureTimeout = null;
      this.captureTimeout = setInterval(this.getOnePacket, 100);
      console.log(this.captureTimeout);
    },
  },
};
</script>
