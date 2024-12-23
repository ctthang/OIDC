<template>
  <iframe
    frameborder="0"
    allowtransparency="true"
    height="0"
    width="0"
    :src="checkSessionIframeUri"
    id="opIFrame"
  ></iframe>
</template>

<script>
import { authService } from './../authService';

export default {
  props: {
    checkSessionIframeUri: {
      type: String,
      required: true,
    },
    opDomain: {
      type: String,
      required: true,
    },
    clientId: {
      type: String,
      required: true,
    },
    sessionState: {
      type: String,
      required: true,
    }
  },
  data() {
    return {
      notice: "Initializing...",
      checkSessionInterval: null,
      errorAction: "",
      stat: "unchanged",
    };
  },
  methods: {
    startSessionCheck() {
      this.notice = "Checking OP Session Status...";
      setTimeout(() => {
        this.checkSessionInterval = setInterval(this.checkSession, 3000);
      }, 3000);
    },

    async checkSession() {
      const opIFrame = document.getElementById("opIFrame");
      if (opIFrame && opIFrame.contentWindow) {
        const message = `${this.clientId} ${this.sessionState}`;
        opIFrame.contentWindow.postMessage(message, this.opDomain);
      }
    },

    receiveMessage(event) {
      if (event.origin != this.opDomain) return;
      this.stat = event.data;
      if (this.stat == "changed") {
        this.notice = "Session has changed. Re-authenticating...";
        this.reauthenticate();
        clearInterval(this.checkSessionInterval);
      }
    },

    reauthenticate() {
      this.notice = "Starting reauthentication...";
      console.log("Reauthenticating...");
      authService.logout();
    },
  },
  mounted() {
    if (window.addEventListener) {
      window.addEventListener("message", this.receiveMessage, false);
    } else if (window.attachEvent) {
      window.attachEvent("onmessage", this.receiveMessage);
    }

    this.startSessionCheck();
  },

  beforeDestroy() {
    if (window.removeEventListener) {
      window.removeEventListener("message", this.receiveMessage, false);
    } else if (window.detachEvent) {
      window.detachEvent("onmessage", this.receiveMessage);
    }

    if (this.checkSessionInterval) {
      clearInterval(this.checkSessionInterval);
    }
  },
};

</script>