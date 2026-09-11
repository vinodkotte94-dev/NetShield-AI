import axios from "axios";

const api = axios.create({
    baseURL: "https://netshield-ai-nq52.onrender.com",
});

export default api;

