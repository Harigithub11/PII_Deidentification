import React from 'react';
import { motion } from 'motion/react';
import { FileText, Shield, Check } from 'lucide-react';

export function PipelineVisualization() {
  return (
    <div className="relative w-full max-w-lg mx-auto">
      {/* Main Pipeline Container */}
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.6, duration: 0.8 }}
        className="relative bg-white/8 backdrop-blur-xl rounded-3xl border border-white/20 p-8 shadow-2xl"
      >
        {/* Background Glow */}
        <div className="absolute inset-0 bg-gradient-to-r from-teal-400/10 to-emerald-400/10 rounded-3xl blur-xl"></div>
        
        {/* Input Documents */}
        <div className="flex items-center justify-between relative z-10">
          <div className="space-y-3">
            <motion.div
              animate={{ x: [0, 5, 0] }}
              transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
              className="flex items-center gap-2"
            >
              <div className="w-4 h-4 bg-teal-500/60 rounded-full shadow-lg"></div>
              <FileText className="w-5 h-5 text-teal-600/80" />
            </motion.div>
            <motion.div
              animate={{ x: [0, 5, 0] }}
              transition={{ duration: 3, repeat: Infinity, ease: "easeInOut", delay: 0.5 }}
              className="flex items-center gap-2"
            >
              <div className="w-4 h-4 bg-teal-500/60 rounded-full shadow-lg"></div>
              <FileText className="w-5 h-5 text-teal-600/80" />
            </motion.div>
            <motion.div
              animate={{ x: [0, 5, 0] }}
              transition={{ duration: 3, repeat: Infinity, ease: "easeInOut", delay: 1 }}
              className="flex items-center gap-2"
            >
              <div className="w-4 h-4 bg-teal-500/60 rounded-full shadow-lg"></div>
              <FileText className="w-5 h-5 text-teal-600/80" />
            </motion.div>
          </div>

          {/* Processing Core */}
          <motion.div
            animate={{ rotate: [0, 360] }}
            transition={{ duration: 12, repeat: Infinity, ease: "linear" }}
            className="mx-8"
          >
            <div className="relative w-20 h-20">
              {/* Hexagonal Pattern */}
              <div className="absolute inset-0 border-2 border-teal-400/40 rounded-2xl transform rotate-45"></div>
              <div className="absolute inset-2 border border-emerald-400/30 rounded-xl transform -rotate-12"></div>
              <div className="absolute inset-4 border border-cyan-400/25 rounded-lg transform rotate-12"></div>
              
              {/* Center Shield */}
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="w-8 h-8 bg-gradient-to-br from-teal-400 to-emerald-500 rounded-xl flex items-center justify-center shadow-lg">
                  <Shield className="w-4 h-4 text-white" />
                </div>
              </div>

              {/* Network Nodes */}
              <motion.div
                animate={{ scale: [1, 1.2, 1], opacity: [0.6, 1, 0.6] }}
                transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
                className="absolute -top-1 left-1/2 w-2 h-2 bg-teal-400 rounded-full transform -translate-x-1/2"
              />
              <motion.div
                animate={{ scale: [1, 1.2, 1], opacity: [0.6, 1, 0.6] }}
                transition={{ duration: 2, repeat: Infinity, ease: "easeInOut", delay: 0.3 }}
                className="absolute -bottom-1 left-1/2 w-2 h-2 bg-emerald-400 rounded-full transform -translate-x-1/2"
              />
              <motion.div
                animate={{ scale: [1, 1.2, 1], opacity: [0.6, 1, 0.6] }}
                transition={{ duration: 2, repeat: Infinity, ease: "easeInOut", delay: 0.6 }}
                className="absolute top-1/2 -left-1 w-2 h-2 bg-cyan-400 rounded-full transform -translate-y-1/2"
              />
              <motion.div
                animate={{ scale: [1, 1.2, 1], opacity: [0.6, 1, 0.6] }}
                transition={{ duration: 2, repeat: Infinity, ease: "easeInOut", delay: 0.9 }}
                className="absolute top-1/2 -right-1 w-2 h-2 bg-teal-400 rounded-full transform -translate-y-1/2"
              />
            </div>
          </motion.div>

          {/* Output Documents */}
          <div className="space-y-3">
            <motion.div
              animate={{ x: [0, -5, 0] }}
              transition={{ duration: 3, repeat: Infinity, ease: "easeInOut", delay: 1.5 }}
              className="flex items-center gap-2"
            >
              <Check className="w-5 h-5 text-emerald-600/80" />
              <div className="w-4 h-4 bg-emerald-500/60 rounded-full shadow-lg"></div>
            </motion.div>
            <motion.div
              animate={{ x: [0, -5, 0] }}
              transition={{ duration: 3, repeat: Infinity, ease: "easeInOut", delay: 2 }}
              className="flex items-center gap-2"
            >
              <Check className="w-5 h-5 text-emerald-600/80" />
              <div className="w-4 h-4 bg-emerald-500/60 rounded-full shadow-lg"></div>
            </motion.div>
            <motion.div
              animate={{ x: [0, -5, 0] }}
              transition={{ duration: 3, repeat: Infinity, ease: "easeInOut", delay: 2.5 }}
              className="flex items-center gap-2"
            >
              <Check className="w-5 h-5 text-emerald-600/80" />
              <div className="w-4 h-4 bg-emerald-500/60 rounded-full shadow-lg"></div>
            </motion.div>
          </div>
        </div>

        {/* Flow Lines */}
        <motion.div
          animate={{ opacity: [0.3, 0.8, 0.3] }}
          transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
          className="absolute top-1/2 left-24 right-24 h-px bg-gradient-to-r from-teal-400/40 via-emerald-400/60 to-teal-400/40 transform -translate-y-1/2"
        />
        
        {/* Flow Particles */}
        <motion.div
          animate={{ x: [-20, 20] }}
          transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
          className="absolute top-1/2 left-24 w-2 h-2 bg-teal-400 rounded-full transform -translate-y-1/2 shadow-lg"
        />
        <motion.div
          animate={{ x: [-20, 20] }}
          transition={{ duration: 3, repeat: Infinity, ease: "easeInOut", delay: 1 }}
          className="absolute top-1/2 left-24 w-1 h-1 bg-emerald-400 rounded-full transform -translate-y-1/2 shadow-lg"
        />
      </motion.div>

      {/* Labels */}
      <div className="flex justify-between mt-4 px-4 text-sm font-medium text-slate-600">
        <span>Raw Data</span>
        <span>AI Processing</span>
        <span>Protected Data</span>
      </div>
    </div>
  );
}